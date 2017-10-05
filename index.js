const crypto = require('crypto')
const moment = require('moment')

const rejector = res => reason => {
  res.status(401).send({
    status: 401,
    reason
  })
}

module.exports = (name, secret, options = {}) => (req, res, next) => {
  options = Object.assign({
    validity: 30,
    rejector
  }, options)

  const cookieHeader = req.headers.cookie
  const reject = options.rejector(res)

  if (!cookieHeader) {
    return reject('no_cookies')
  }

  const cookies = cookieHeader
    .split('; ')
    .map(str => {
      const [key, val] = str.split('=')
      return {key, val: decodeURIComponent(val)}
    })

  const cookie = cookies.find(x => x.key === name)
  if (!cookie) {
    return reject(`no_${name}_cookie`)
  }

  const cookieValue = cookie.val
  if (!cookieValue) {
    return reject(`no_${name}_cookie_value`)
  }

  const [version, userId, created, sig] = cookieValue.split('|')

  if (version !== 'v1') {
    return reject('invalid_version')
  }

  const validFrom = moment().add(-options.validity, 'days')
  const validTo = moment()
  if (!moment(created).isBetween(validFrom, validTo)) {
    return reject('expired_token')
  }

  const token = `v1|${userId}|${created}`

  const hash = crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('base64')
    .replace(/[+\/=]/g, c => ({'+':'-','//':'_','=':''}[c]))

  if (hash !== sig) {
    console.log(`invalid_signature ${hash} !== ${sig}`)
    return reject(`invalid_signature ${sig}`)
  }

  req.userId = userId
  return next()
}

module.exports.sign = (userId, secret) => {
  const created = moment().format()
  const token = `v1|${userId}|${created}`
  const sig = crypto
    .createHmac('sha256', secret)
    .update(token)
    .digest('base64')
    .replace(/[+\/=]/g, c => ({'+':'-','//':'_','=':''}[c]))
  return `${token}|${sig}`
}