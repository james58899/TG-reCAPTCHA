# tg-recaptcha
reCAPTCHA bot for telegram

## Usage
1. Add bot to group
   * Using an existing bot `@simple_reCAPTCHA_bot`(DC1) or `@Simple_reCAPTCHA_2bot`(DC5)
   * Refer to deployment to deploy the bot yourself
2. Promote bot to administrator
   * Delete messages (Used to delete join notification)
   * Ban users (Used to restrict new members and kick out)
   * Add users (Used to approve join requests)

## Verification procedure
### Normal join
1. User join
2. Bot mute new user
3. Bot sends message for verification
4. User clicks the button to open the verification page
5. Verify via reCAPTCHA
6. Bot unmute user or timeout kick user
7. Bot delete verification message

### Join request
1. User send join request
2. Bot send private message for verification
3. User clicks the button to open the verification page
4. Verify via reCAPTCHA
5. Bot approve join request or timeout decline join request
6. Bot delete verification message

## Config
|    Field    |                                         Description                                          |
| ----------- | -------------------------------------------------------------------------------------------- |
| `api_base`  | Telegram bot api base url, for local telegram bot server, leave empty to use default server. |
| `token`     | Telegram bot api token.                                                                      |
| `url`       | The URL used to serve the verification page.                                                 |
| `bind`      | The address the bot listens on, leave it empty to listen on all.                             |
| `port`      | The port that the bot listens on.                                                            |
| `webhook`   | Use webhooks instead of polling to receive Telegram updates.                                 |
| `recaptcha` | reCAPTCHA keys.                                                                              |
| `redis`     | Use redis to store timeout data, leave it blank to use memory storage.                       |
| `timeout`   | Verification timeout in seconds.                                                             |

## Deployment
### Direct run
1. Use git or download the entire repo directly
2. Copy `config_example.json` to `config.json` and change the content.
3. Run `yarn node index.js`

### Docker
1. Build or use an image from Docker Hub.
2. Create `config.json` and fill the content.
3. `docker run --network host --restart unless-stopped -d -v config.json:/app/config.json -p <port> <image>`
