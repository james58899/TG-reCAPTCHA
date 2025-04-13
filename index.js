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
  params: { timeout: 60, allowed_updates: JSON.stringify(["message", "callback_query", "chat_member"]) }
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

      // unban & response
      bot.getChatMember(data.chat, req.query.id).then(member => {
        if (member.status === "restricted") {
          bot.restrictChatMember(data.chat, req.query.id, unban).catch(e => console.trace("[Pass] Unban failed.", e.stack))
        }
      }).catch(e => console.trace("[Pass] Get chat member failed.", e.stack))
      res.send()

      // Remove timeout countdown & Update or delete message
      removeTimeout(data.time, parseInt(req.query.id)).then(users => {
        if (users.length === 0) {
          bot.deleteMessage(data.chat, data.id).catch(e => console.trace("[Pass] delete message failed.", e.stack))
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
  // Only trigger on join
  const oldStatus = event.old_chat_member
  const newStatus = event.new_chat_member
  let muteJoin = false
  if (newStatus.status === "member" && ["left", "kicked"].includes(oldStatus.status)) {
    muteJoin = await bot.restrictChatMember(event.chat.id, newStatus.user.id, { can_send_messages: false }).catch(() => false)
  } else return

  // Only send message with user if not join message
  let chatInfo = bot.getChat(event.chat.id);
  let memberCount = bot.getChatMemberCount(event.chat.id);
  if (!muteJoin || !(await chatInfo).has_hidden_members && (await memberCount) < 10000) return

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

bot.on('new_chat_members', async msg => {
  const members = msg.new_chat_members.filter(i => !i.is_bot)

  if (members.length === 0) return

  // This will mute member double time, just check bot has permission
  const muteJoin = await Promise.allSettled(members.map(i => bot.restrictChatMember(msg.chat.id, i.id, { can_send_messages: false })))
  if (muteJoin.every(i => i.status === "rejected")) return

  let message
  try {
    message = await retryCooldown(() => bot.sendMessage(msg.chat.id, 'Generating token...', { reply_to_message_id: msg.message_id }))
  } catch (e) {
    console.trace("[Join] Send message failed.", e.stack)
    return
  }

  await sleep(1000) // Wait client sync...

  const time = getUnixtime()
  retryCooldown(() => bot.editMessageText("Are you a robot?", {
    chat_id: message.chat.id,
    message_id: message.message_id,
    reply_markup: genKeyboard(genToken(time, msg.chat.id, message.message_id, members.map(i => i.id)))
  })).catch(e => console.trace("[Join] Edit message failed.", e.stack))

  addTimeout(time, { chat: msg.chat.id, users: members.map(i => i.id), id: message.message_id, msg: msg.message_id })
})

// Delete kick message
bot.on('left_chat_member', async msg => {
  if (msg.from.id === me) bot.deleteMessage(msg.chat.id, msg.message_id)
})

bot.on('callback_query', async callback => {
  const data = parserToken(callback.message.reply_markup.inline_keyboard[0][0].url.split('/').pop())

  const users = await Promise.all(data.users.map(i => bot.getChatMember(data.chat, i)))

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

function parserToken(input) {
  const rawdata = Buffer.from(input, 'base64url')
  const hash = rawdata.subarray(0, 32)
  const data = rawdata.subarray(32)

  if (hash.equals(crypto.createHmac('sha256', secretKey).update(data).digest())) {
    return JSON.parse(data.toString('latin1'))
  }
}

function genToken(time, chat, id, users) {
  const data = JSON.stringify({ chat, id, users, time, ts: getUnixtime() })
  const hash = crypto.createHmac('sha256', secretKey).update(data).digest()
  return Buffer.concat([hash, Buffer.from(data, 'latin1')]).toString('base64url')
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

function addTimeout(time, data) {
  if (redisClient) {
    redisClient.zAdd("timeout", { score: time, value: JSON.stringify(data) })
  } else {
    timeout.has(time) ? timeout.get(time).push(data) : timeout.set(time, [data])
  }
}

/**
 * 
 * @param {Number} time
 * @param {Number} user
 * @returns {Promise<Array<Number>>}
 */
async function removeTimeout(time, user) {
  let pending = []
  if (redisClient) {
    for (const value of (await redisClient.zRangeByScore("timeout", time, time))) {
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

async function cleanTimeout(value) {
  let deleteJoin = false
  for (const user of value.users) {
    try {
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
    if (await bot.deleteMessage(value.chat, value.id) && deleteJoin && value.msg) await bot.deleteMessage(value.chat, value.msg)
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