const crypto = require('crypto')
const express = require('express')
const morgan = require('morgan')
const { Bot, TelegramApiError } = require('node-telegram-bot-api')
const Recaptcha = require('express-recaptcha').RecaptchaV2
const redis = require("redis")
const config = require('./config.json')

const secretKey = crypto.createHash('sha256').update(config.token).digest()
const webAppKey = crypto.createHmac('sha256', 'WebAppData').update(config.token).digest()
const allowedUpdates = ["message", "callback_query", "chat_member", "chat_join_request"];
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

const bot = new Bot(config.token, { apiRoot: config.api_base })
const app = express()
const recaptcha = new Recaptcha(config.recaptcha.site_key, config.recaptcha.secret_key, { checkremoteip: true, callback: 'cb' })
/** @type {import('redis').RedisClientType} */
let redisClient
/** @type {Map<Number, Array} */
let timeout
let me = 0;
let username = '';

bot.api.getMe().then(i => {
  me = i.id
  username = i.username
}).catch(e => {
  // Links need the username, let the process manager restart us
  console.error("[Init] Get me failed.", e)
  process.exit(1)
});

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
    bot.handleUpdate(req.body) // TODO check
  })

  bot.api.setWebhook({ url: `${config.url}/bot${config.token}`, allowed_updates: allowedUpdates })
} else {
  bot.api.deleteWebhook().then(() => bot.startPolling(undefined, { allowedUpdates }))
}

// Skip webhook logging
app.use(morgan('combined'))
app.get('/', (_, res) => res.send('Hello world!'))
app.get('/robots.txt', (_, res) => {
  res.set('Content-Type', 'text/plain')
  res.send('User-agent: *\nDisallow: /')
})
// Mini App URL, set to `${config.url}/verify` in BotFather (Main Mini App or /newapp)
app.get('/verify', recaptcha.middleware.renderWith({ onload: 'onRecaptcha', render: 'explicit' }), (req, res) => {
  res.set('Cache-Control', 'public, max-age=30, must-revalidate')
  // `token` from guard bot join request
  const data = parserToken(req.query.tgWebAppStartParam || req.query.token)
  const now = getUnixtime()
  // Skip 60s expiry for guard bot token
  if (!data || !data.query && now - data.ts > 60) {
    res.status(403).render('verify', { error: 'Token expired, please click Update token and try again.' })
    return
  }

  res.render('verify', { captcha: res.recaptcha, users: data.users })
})
app.post('/verify', recaptcha.middleware.verify, async (req, res) => {
  if (req.recaptcha.error) {
    res.status(400).send('reCAPTCHA vailed failed.')
    return
  }
  const initData = checkVaild(req.body.initData)
  if (!initData) {
    res.status(401).send('Auth failed, please try again.')
    return
  }
  const data = parserToken(initData.get('start_param') || req.query.token)
  const now = getUnixtime()
  // Join request query token can't be refreshed, bind it to the signed query id instead of expiring
  const expired = data && (data.query ? data.query !== initData.get('chat_join_request_query_id') : now - data.ts > 60 || now - initData.get('auth_date') > 60)
  if (!data || expired) {
    res.status(410).send('Token expired, please click Update token and try again.')
    return
  }
  const user_id = JSON.parse(initData.get('user')).id

  if (!data.users.includes(parseInt(user_id))) {
    res.status(400).send("User not match token")
    return
  }

  if (data.query) {
    // Join request query
    bot.api.answerChatJoinRequestQuery({ chat_join_request_query_id: data.query, result: 'approve' }).catch(e => console.trace("[Pass] Answer join request query failed.", e.stack))
  } else if (data.user_chat) {
    // Join request
    bot.api.approveChatJoinRequest({ chat_id: data.chat, user_id }).catch(e => console.trace("[Pass] Approve chat join request failed.", e.stack))
  } else {
    // Unban
    bot.api.getChatMember({ chat_id: data.chat, user_id }).then(member => {
      if (member.status === "restricted") {
        bot.api.restrictChatMember({ chat_id: data.chat, user_id, permissions: unban }).catch(e => console.trace("[Pass] Unban failed.", e.stack))
      }
    }).catch(e => console.trace("[Pass] Get chat member failed.", e.stack))
  }
  res.send()

  // Remove timeout countdown & Update or delete message
  removeTimeout(data.time, parseInt(user_id)).then(users => {
    if (data.query) return // No message
    if (users.length === 0) {
      bot.api.deleteMessage({ chat_id: data.user_chat || data.chat, message_id: data.id }).catch(e => console.trace("[Pass] delete message failed.", e.stack))
    } else {
      retryCooldown(() => bot.api.editMessageReplyMarkup({ chat_id: data.chat, message_id: data.id, reply_markup: genKeyboard(genToken(data.time, data.chat, data.id, users)) }))
        .catch(e => console.trace("[Pass] Update message failed.", e.stack))
    }
  })
})

app.listen(config.port, config.bind, () => console.log(`app listening on port ${config.port}!`)).keepAliveTimeout = 15 * 60 * 1000

bot.hears(/^\/ping(?:@\w+)?/, async msg => {
  retryCooldown(() => bot.api.sendMessage({ chat_id: msg.chat.id, text: "pong", reply_to_message_id: msg.message.message_id }))
})

bot.hears(/^\/privacy/, async msg => {
  retryCooldown(() => bot.api.sendMessage({ chat_id: msg.chat.id, text: "This bot will store access logs for debugging and security purposes.", reply_to_message_id: msg.message.message_id }))
})

bot.on('chat_member', async ctx => {
  const event = ctx.update.chat_member
  // Skip join request
  if (event.via_join_request || event.from.id === me || (event.invite_link && event.invite_link.creates_join_request)) return

  // Only trigger on join
  const oldStatus = event.old_chat_member
  const newStatus = event.new_chat_member
  let muteJoin = false
  if (newStatus.status === "member" && ["left", "kicked"].includes(oldStatus.status)) {
    muteJoin = await bot.api.restrictChatMember({ chat_id: event.chat.id, user_id: newStatus.user.id, can_send_messages: false }).catch(() => false)
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
    message = await retryCooldown(() => bot.api.sendMessage({
      chat_id: event.chat.id,
      text: `${name} are you a robot?\n\nGenerating token...`,
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
  retryCooldown(() => bot.api.editMessageText({
    chat_id: message.chat.id,
    message_id: message.message_id,
    text: `${name} are you a robot?`,
    entities: [{ type: "text_mention", offset: 0, length: name.length, user: { id: newStatus.user.id } }],
    reply_markup: genKeyboard(genToken(time, event.chat.id, message.message_id, [newStatus.user.id]))
  })).catch(e => console.trace("[Join] Edit message failed.", e.stack))

  addTimeout(time, { chat: event.chat.id, users: [newStatus.user.id], id: message.message_id })
})

// Delete join/kick message
bot.on('message', async ctx => {
  const msg = ctx.update.message;
  if (msg.new_chat_members || msg.left_chat_member && msg.from.id === me) {
    bot.api.deleteMessage({ chat_id: msg.chat.id, message_id: msg.message_id }).catch(e => { })
  }
})

bot.on('chat_join_request', async ctx => {
  const request = ctx.update.chat_join_request;
  // Guard bot
  if (request.query_id) {
    const time = getUnixtime()
    const token = genToken(time, request.chat.id, 0, [request.from.id], undefined, request.query_id)
    try {
      await bot.api.sendChatJoinRequestWebApp({ chat_join_request_query_id: request.query_id, web_app_url: `${config.url}/verify?token=${token}` })
      addTimeout(time, { chat: request.chat.id, users: [request.from.id], query: request.query_id })
    } catch (e) {
      console.trace("[Join request] Send web app failed.", e.stack)
    }
    return
  }

  // Send message
  let message
  try {
    message = await retryCooldown(() => bot.api.sendMessage({
      chat_id: request.user_chat_id,
      text: `You requested to join ${request.chat.title}!\nAre you a robot?\n\nGenerating token...`,
      protect_content: true
    }
    ))
  } catch (e) {
    console.trace("[Join request] Send message failed.", e.stack)
    return
  }

  await sleep(1000) // Wait client sync...

  const time = getUnixtime()
  retryCooldown(() => bot.api.editMessageText({
    chat_id: message.chat.id,
    message_id: message.message_id,
    text: `You requested to join ${request.chat.title}!\nAre you a robot?`,
    reply_markup: genKeyboard(genToken(time, request.chat.id, message.message_id, [request.from.id], request.user_chat_id))
  })).catch(e => console.trace("[Join request] Edit message failed.", e.stack))

  addTimeout(time, { chat: request.chat.id, users: [request.from.id], id: message.message_id, user_chat: request.user_chat_id })
})

bot.on('callback_query', async ctx => {
  const query = ctx.update.callback_query
  const data = parserToken(query.message.reply_markup.inline_keyboard[0][0].url.split('startapp=').pop())

  const users = await Promise.all(data.users.map(i => bot.api.getChatMember({ chat_id: data.chat, user_id: i })))

  // Always refresh on join request
  if (data.user_chat) {
    if (users[0].status === 'member') {
      bot.api.deleteMessage({ chat_id: data.user_chat, message_id: data.id }).catch(e => console.trace("[Callback] Delete message failed.", e.stack))
    } else {
      const token = genToken(data.time, data.chat, data.id, data.users, data.user_chat)
      bot.api.editMessageReplyMarkup({ chat_id: data.user_chat, message_id: data.id, reply_markup: genKeyboard(token) })
        .catch(e => console.trace("[Callback] Edit message failed.", e.stack))
      bot.api.answerCallbackQuery({ callback_query_id: query.id, cache_time: 30, text: 'Token updated' })
    }
    return
  }

  const unvailedUsers = users.filter(i => i.status === 'restricted').map(i => i.user.id)
  if (unvailedUsers.length === 0) {
    bot.api.deleteMessage({ chat_id: data.chat, message_id: data.id }).catch(e => console.trace("[Callback] Delete message failed.", e.stack))
    bot.api.answerCallbackQuery({ callback_query_id: query.id })
  } else if (unvailedUsers.includes(query.from.id)) {
    bot.api.editMessageReplyMarkup({ chat_id: data.chat, message_id: data.id, reply_markup: genKeyboard(genToken(data.time, data.chat, data.id, unvailedUsers)) })
      .catch(e => console.trace("[Callback] Edit message failed.", e.stack))
    bot.api.answerCallbackQuery({ callback_query_id: query.id, cache_time: 30, text: 'Token updated' })
  } else {
    bot.api.answerCallbackQuery({ callback_query_id: query.id, cache_time: 300 })
  }

  const vailedUsers = users.filter(i => i.status !== 'restricted').map(i => i.user.id)
  if (vailedUsers.length !== 0) {
    await Promise.all(vailedUsers.map(i => removeTimeout(data.time, i)))
  }
})

/**
 * Validate Telegram WebApp initData
 * @param {String} input - Raw initData query string
 * @returns {?URLSearchParams} Parsed params if valid
 */
function checkVaild(input) {
  if (typeof input !== 'string') return null
  const params = new URLSearchParams(input)
  const hash = params.get('hash')
  params.delete('hash')
  const data = [...params].map(([key, value]) => `${key}=${value}`).sort().join('\n')

  return hash === crypto.createHmac('sha256', webAppKey).update(data).digest('hex') ? params : null
}

/**
 * @typedef {Object} TokenData
 * @property {Number} chat - Chat ID
 * @property {Number} id - Verify message ID
 * @property {Array<Number>} users - User IDs
 * @property {Number} time - Data timestamp
 * @property {Number} ts - Token generated timestamp
 * @property {?Number} user_chat - Private chat ID
 * @property {?String} query - Join request query ID
 */

/**
 * Parse token
 * @param {String} input - Base64 URL encoded token
 * @returns {TokenData} Parsed token data
 */
function parserToken(input) {
  if (typeof input !== 'string') return
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
 * @param {?String} query - Join request query ID
 * @returns {String} base64url encoded string of {@link TokenData}
 */
function genToken(time, chat, id, users, user_chat, query) {
  let data = { chat, id, users, time, ts: getUnixtime() }
  if (user_chat) data.user_chat = user_chat
  if (query) data.query = query
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
      [{ text: "I'm not a robot", url: `https://t.me/${username}${config.app_name ? `/${config.app_name}` : ''}?mode=compact&startapp=${token}` }],
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
 * @property {?String} query - Join request query ID
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
      if (value.query) {
        bot.api.answerChatJoinRequestQuery({ chat_join_request_query_id: value.query, result: 'decline' }).catch(e => { })
        continue
      }
      // Decline join request
      if (value.user_chat) {
        bot.api.declineChatJoinRequest({ chat_id: value.chat, user_id: user }).catch(e => { })
        continue
      }

      const member = await bot.api.getChatMember({ chat_id: value.chat, user_id: user })
      if (member.status === "restricted") {
        deleteJoin = true
        if (member.is_member === true) {
          await retryCooldown(() => bot.api.banChatMember({ chat_id: value.chat, user_id: member.user.id, until_date: Math.floor(+new Date() / 1000) + 60 }))
          await sleep(1000) // Workaround TG API laggy
          await retryCooldown(() => bot.api.unbanChatMember({ chat_id: value.chat, user_id: member.user.id, only_if_banned: true }))
        } else {
          await retryCooldown(() => bot.api.unbanChatMember({ chat_id: value.chat, user_id: member.user.id }))
        }
      } else if (member.status === "kicked") {
        deleteJoin = true
      }
    } catch (error) {
      console.trace("[Timeout] Kick failed.", error.stack)
    }
  }
  if (value.query) return // No message
  try {
    await bot.api.deleteMessage({ chat_id: value.user_chat || value.chat, message_id: value.id })
  } catch (error) { }
}

function sleep(time) {
  return new Promise(resolve => setTimeout(resolve, time));
}

async function retryCooldown(request) {
  try {
    return await request()
  } catch (error) {
    console.log(error)
    if (error instanceof TelegramApiError && error.errorCode === 429) {
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

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
