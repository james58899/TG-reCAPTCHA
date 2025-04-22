const crypto = require('crypto')
const express = require('express')
const morgan = require('morgan')
const telegrambot = require('node-telegram-bot-api')
const Recaptcha = require('express-recaptcha').RecaptchaV2
const redis = require("redis")
const util = require('util');
const config = require('./config.json')

const secretKey = crypto.createHash('sha256').update(config.token).digest()
const pollingOption = {
  interval: 0,
  params: { timeout: 60, allowed_updates: JSON.stringify(["message", "callback_query", "chat_member", "chat_join_request"]) }
}
const unban = {
  can_send_messages: true,
  can_send_media_messages: true,
  can_send_polls: true,
  can_send_other_messages: true,
  can_add_web_page_previews: true,
  can_change_info: true,
  can_invite_users: true,
  can_pin_messages: true
}

const bot = new telegrambot(config.token, { polling: config.webhook ? false : pollingOption, baseApiUrl: config.api_base })
const app = express()
const recaptcha = new Recaptcha(config.recaptcha.site_key, config.recaptcha.secret_key, { checkremoteip: true, callback: 'cb' })
/** @type {import('redis').RedisClientType} */
let redisClient
/** @type {Map<Number, Array} */
let timeout
let me = 0;

bot.getMe().then(i => me = i.id);

if (config.redis && config.redis != "") {
  redisClient = redis.createClient(config.redis)
  redisClient.on("ready", () => console.log("Redis ready."))
  redisClient.on("error", console.error)
  redisClient.connect()
} else {
  timeout = new Map()
}

if (!config.timeout) config.timeout = 3600

setInterval(doTimeout, Math.min(60000, config.timeout * 1000))

recaptcha._api.host = 'www.recaptcha.net'
app.disable('x-powered-by')
app.set('view engine', 'pug')
app.set('trust proxy', true)
app.use(express.json())

if (config.webhook) {
  app.post(`/bot${config.token}`, (req, res) => {
    res.sendStatus(200)
    bot.processUpdate(req.body)
  })

  bot.setWebHook(`${config.url}/bot${config.token}`)
}

// Skip webhook logging
app.use(morgan('combined'))
app.get('/', (_, res) => res.send('Hello world!'))
app.get('/robots.txt', (_, res) => {
  res.set('Content-Type', 'text/plain')
  res.send('User-agent: *\nDisallow: /')
})
app.get('/verify/:token', recaptcha.middleware.render, (req, res) => {
  res.set('Cache-Control', 'public, max-age=30')
  if (req.query.hash) {
    const data = parserToken(req.params.token)
    const now = getUnixtime()

    if (!data || now - req.query.auth_date > 60 || now - data.ts > 60) {
      res.status(403).send("Token expired, please click <b>Update token</b> and try again.")
      return
    }

    if (!checkVaild(req.query)) {
      res.status(401).send("Auth failed, please try again.")
      return
    }

    if (!data.users.includes(parseInt(req.query.id))) {
      res.status(400).send("User not match token")
      return
    }

    res.render('verify', { captcha: res.recaptcha })
    return
  }

  // todo generate auth token whitout login
  res.status(400).send('Need login to know who you are.')
})
app.post('/verify/:token', recaptcha.middleware.verify, (req, res) => {
  if (req.query.hash && checkVaild(req.query, req.query.hash)) {
    if (!req.recaptcha.error) {
      const data = parserToken(req.params.token)

      if (getUnixtime() - data.ts > 60) {
        res.status(410).send('Token expired')
        return
      }

      if (data.user_chat) {
        // Join request
        bot.approveChatJoinRequest(data.chat, req.query.id).catch(e => console.trace("[Pass] Approve chat join request failed.", e.stack))
      } else {
        // Unban
        bot.getChatMember(data.chat, req.query.id).then(member => {
          if (member.status === "restricted") {
            bot.restrictChatMember(data.chat, req.query.id, unban).catch(e => console.trace("[Pass] Unban failed.", e.stack))
          }
        }).catch(e => console.trace("[Pass] Get chat member failed.", e.stack))
      }
      res.send()

      // Remove timeout countdown & Update or delete message
      removeTimeout(data.time, parseInt(req.query.id)).then(users => {
        if (users.length === 0) {
          bot.deleteMessage(data.user_chat || data.chat, data.id).catch(e => console.trace("[Pass] delete message failed.", e.stack))
        } else {
          retryCooldown(() => bot.editMessageReplyMarkup(genKeyboard(genToken(data.time, data.chat, data.id, users)), { chat_id: data.chat, message_id: data.id }))
            .catch(e => console.trace("[Pass] Update message failed.", e.stack))
        }
      })
    } else {
      res.status(400).send('reCAPTCHA vailed failed.')
    }
  }
})

app.listen(config.port, config.bind, () => console.log(`app listening on port ${config.port}!`)).keepAliveTimeout = 15 * 60 * 1000

bot.onText(/^\/ping(?:@\w+)?/, async msg => {
  retryCooldown(() => bot.sendMessage(msg.chat.id, "pong", { reply_to_message_id: msg.message_id }))
})

bot.onText(/^\/privacy/, async msg => {
  retryCooldown(() => bot.sendMessage(msg.chat.id, "This bot will store access logs for debugging and security purposes.", { reply_to_message_id: msg.message_id }))
})

bot.on('chat_member', async event => {
  // Skip join request
  if (event.via_join_request || event.from.id === me || (event.invite_link && event.invite_link.creates_join_request)) return

  // Only trigger on join
  const oldStatus = event.old_chat_member
  const newStatus = event.new_chat_member
  let muteJoin = false
  if (newStatus.status === "member" && ["left", "kicked"].includes(oldStatus.status)) {
    muteJoin = await bot.restrictChatMember(event.chat.id, newStatus.user.id, { can_send_messages: false }).catch(() => false)
  } else return
  if (!muteJoin) return

  // Send message
  let message
  let name = newStatus.user.username
  if (newStatus.user.username) {
    name = '@' + newStatus.user.username
  } else {
    name = newStatus.user.first_name
    let graphemes = [...(new Intl.Segmenter()).segment(name)] // unicode graphemes
    if (graphemes.length > 10) {
      name = graphemes.slice(0, 10).map(s => s.segment).join('') + '...'
    }
  }
  try {
    message = await retryCooldown(() => bot.sendMessage(event.chat.id,
      `${name} are you a robot?\n\nGenerating token...`,
      {
        protect_content: true,
        entities: [{ type: "text_mention", offset: 0, length: name.length, user: { id: newStatus.user.id } }]
      }
    ))
  } catch (e) {
    console.trace("[Join] Send message failed.", e.stack)
    return
  }

  await sleep(1000) // Wait client sync...

  const time = getUnixtime()
  retryCooldown(() => bot.editMessageText(`${name} are you a robot?`, {
    chat_id: message.chat.id,
    message_id: message.message_id,
    entities: [{ type: "text_mention", offset: 0, length: name.length, user: { id: newStatus.user.id } }],
    reply_markup: genKeyboard(genToken(time, event.chat.id, message.message_id, [newStatus.user.id]))
  })).catch(e => console.trace("[Join] Edit message failed.", e.stack))

  addTimeout(time, { chat: event.chat.id, users: [newStatus.user.id], id: message.message_id })
})

// Delete join message
bot.on('new_chat_members', async msg => {
  bot.deleteMessage(msg.chat.id, msg.message_id).catch(e => { })
})

// Delete kick message
bot.on('left_chat_member', async msg => {
  if (msg.from.id === me) bot.deleteMessage(msg.chat.id, msg.message_id)
})

bot.on('chat_join_request', async event => {
  // Send message
  let message
  try {
    message = await retryCooldown(() => bot.sendMessage(event.user_chat_id,
      `You requested to join ${event.chat.title}, are you a robot?\n\nGenerating token...`,
      { protect_content: true }
    ))
  } catch (e) {
    console.trace("[Join request] Send message failed.", e.stack)
    return
  }

  await sleep(1000) // Wait client sync...

  const time = getUnixtime()
  retryCooldown(() => bot.editMessageText(`You requested to join ${event.chat.title}, are you a robot?`, {
    chat_id: message.chat.id,
    message_id: message.message_id,
    reply_markup: genKeyboard(genToken(time, event.chat.id, message.message_id, [event.from.id], event.user_chat_id))
  })).catch(e => console.trace("[Join request] Edit message failed.", e.stack))

  addTimeout(time, { chat: event.chat.id, users: [event.from.id], id: message.message_id, user_chat: event.user_chat_id })
})

bot.on('callback_query', async callback => {
  const data = parserToken(callback.message.reply_markup.inline_keyboard[0][0].url.split('/').pop())

  const users = await Promise.all(data.users.map(i => bot.getChatMember(data.chat, i)))

  // Always refresh on join request
  if (data.user_chat) {
    if (users[0].status === 'member') {
      bot.deleteMessage(data.user_chat, data.id).catch(e => console.trace("[Callback] Delete message failed.", e.stack))
    } else {
      const token = genToken(data.time, data.chat, data.id, data.users, data.user_chat)
      bot.editMessageReplyMarkup(genKeyboard(token), { chat_id: data.user_chat, message_id: data.id })
        .catch(e => console.trace("[Callback] Edit message failed.", e.stack))
      bot.answerCallbackQuery(callback.id, { cache_time: 30, text: 'Token updated' })
    }
    return
  }

  const unvailedUsers = users.filter(i => i.status === 'restricted').map(i => i.user.id)
  if (unvailedUsers.length === 0) {
    bot.deleteMessage(data.chat, data.id).catch(e => console.trace("[Callback] Delete message failed.", e.stack))
    bot.answerCallbackQuery(callback.id)
  } else if (unvailedUsers.includes(callback.from.id)) {
    bot.editMessageReplyMarkup(genKeyboard(genToken(data.time, data.chat, data.id, unvailedUsers)), { chat_id: data.chat, message_id: data.id })
      .catch(e => console.trace("[Callback] Edit message failed.", e.stack))
    bot.answerCallbackQuery(callback.id, { cache_time: 30, text: 'Token updated' })
  } else {
    bot.answerCallbackQuery(callback.id, { cache_time: 300 })
  }

  const vailedUsers = users.filter(i => i.status !== 'restricted').map(i => i.user.id)
  if (vailedUsers.length !== 0) {
    await Promise.all(vailedUsers.map(i => removeTimeout(data.time, i)))
  }
})

function checkVaild(input) {
  const data = Object.keys(input).sort().reduce((acc, key, index) => {
    if (key === 'hash') return acc
    if (index !== 0) acc += '\n'
    return acc + `${key}=${input[key]}`
  }, '')

  return input.hash === crypto.createHmac('sha256', secretKey).update(data).digest('hex')
}

/**
 * @typedef {Object} TokenData
 * @property {Number} chat - Chat ID
 * @property {Number} id - Verify message ID
 * @property {Array<Number>} users - User IDs
 * @property {Number} time - Data timestamp
 * @property {Number} ts - Token generated timestamp
 * @property {?Number} user_chat - Private chat ID
 */

/**
 * Parse token
 * @param {String} input - Base64 URL encoded token
 * @returns {TokenData} Parsed token data
 */
function parserToken(input) {
  const rawdata = Buffer.from(input, 'base64url')
  const hash = rawdata.subarray(0, 32)
  const data = rawdata.subarray(32)

  if (hash.equals(crypto.createHmac('sha256', secretKey).update(data).digest())) {
    return JSON.parse(data.toString('latin1'))
  }
}

/**
 * Generate token
 * @param {Number} time - Timestamp
 * @param {Number} chat - Chat ID
 * @param {Number} id - Verify message ID
 * @param {Array<Number>} users - User IDs
 * @param {?Number} user_chat - Private chat ID
 * @returns {String} base64url encoded string of {@link TokenData}
 */
function genToken(time, chat, id, users, user_chat) {
  let data = { chat, id, users, time, ts: getUnixtime() }
  if (user_chat) data.user_chat = user_chat
  const json = JSON.stringify(data)
  const hash = crypto.createHmac('sha256', secretKey).update(json).digest()
  return Buffer.concat([hash, Buffer.from(json, 'latin1')]).toString('base64url')
}

function getUnixtime() {
  return Date.now() / 1000 | 0
}

function genKeyboard(token) {
  return {
    inline_keyboard: [
      [{ text: "I'm not a robot", login_url: { url: `${config.url}/verify/${token}` } }],
      [{ text: "Update token", callback_data: "update" }]
    ]
  }
}

/** 
 * @typedef {Object} TimeoutData
 * @property {Number} chat - Chat ID
 * @property {Array<Number>} users - User IDs
 * @property {Number} id - Verify message ID
 * @property {?Number} user_chat - Private chat ID
 */

/**
 * @param {Number} time timestamp
 * @param {TimeoutData} data
 */
function addTimeout(time, data) {
  if (redisClient) {
    redisClient.zAdd("timeout", { score: time, value: JSON.stringify(data) })
  } else {
    timeout.has(time) ? timeout.get(time).push(data) : timeout.set(time, [data])
  }
}

/**
 * 
 * @param {Number} time - Timestamp
 * @param {Number} user - Passed user
 * @returns {Promise<Array<Number>>} - Unvailed users
 */
async function removeTimeout(time, user) {
  let pending = []
  if (redisClient) {
    for (const value of (await redisClient.zRangeByScore("timeout", time, time))) {
      /** @type {TokenData} */
      const data = JSON.parse(value)

      const index = data.users.indexOf(user);
      if (index > -1) {
        data.users.splice(index, 1);
        pending = data.users
      } else continue

      if (data.users.length === 0) {
        redisClient.zRem("timeout", value)
      } else {
        // Update data
        redisClient.multi().zRem("timeout", value).zAdd("timeout", { score: time, value: JSON.stringify(data) }).exec()
      }
    }
  } else if (timeout.has(time)) {
    const updated = timeout.get(time).filter((data) => {
      // Remove user from array
      const index = data.users.indexOf(user);
      if (index > -1) {
        data.users.splice(index, 1);
        pending = data.users
      }
      return data.users.length !== 0
    })

    updated.length === 0 ? timeout.delete(time) : timeout.set(time, updated)
  }
  return pending
}

async function doTimeout() {
  const time = getUnixtime() - config.timeout
  if (redisClient) {
    if (await redisClient.zCount("timeout", 0, time) != 0) {
      for (const value of (await redisClient.zRangeByScore("timeout", 0, time)).map(i => JSON.parse(i))) {
        cleanTimeout(value)
      }
      redisClient.zRemRangeByScore("timeout", 0, time)
    }
  } else {
    timeout.forEach((value, key) => {
      if (key < time) {
        for (const i of value) cleanTimeout(i)
        timeout.delete(key)
      }
    })
  }
}

/**
 * @param {TimeoutData} value
 * @returns {Promise<void>}
 */
async function cleanTimeout(value) {
  let deleteJoin = false
  for (const user of value.users) {
    try {
      // Decline join request
      if (value.user_chat) {
        bot.declineChatJoinRequest(value.chat, user).catch(e => { })
        continue
      }

      const member = await bot.getChatMember(value.chat, user)
      if (member.status === "restricted") {
        deleteJoin = true
        if (member.is_member === true) {
          await retryCooldown(() => bot.banChatMember(value.chat, member.user.id, { until_date: Math.floor(+new Date() / 1000) + 60 }))
          await sleep(1000) // Workaround TG API laggy
          await retryCooldown(() => bot.unbanChatMember(value.chat, member.user.id, { only_if_banned: true }))
        } else {
          await retryCooldown(() => bot.unbanChatMember(value.chat, member.user.id))
        }
      } else if (member.status === "kicked") {
        deleteJoin = true
      }
    } catch (error) {
      console.trace("[Timeout] Kick failed.", error.stack)
    }
  }
  try {
    bot.deleteMessage(value.user_chat || value.chat, value.id)
  } catch (error) { }
}

function sleep(time) {
  return new Promise(resolve => setTimeout(resolve, time));
}

async function retryCooldown(request) {
  try {
    return await request()
  } catch (error) {
    if (error.code === "ETELEGRAM" && error.response.statusCode === 429) {
      const delayTime = error.message.split(' ').pop()

      if (isNaN(delayTime)) throw error

      await sleep(delayTime * 1000)
      return retryCooldown(request)
    } else if (error.response && error.response.statusCode >= 500) {
      await sleep(1000)
      return retryCooldown(request)
    } else throw error
  }
}