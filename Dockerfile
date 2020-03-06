FROM node:lts-alpine
WORKDIR /app
ENV NODE_ENV=production

COPY package.json yarn.lock .yarnrc.yml .pnp.js ./
COPY .yarn .yarn

RUN yarn install --immutable

COPY views views
COPY index.js config_example.json ./

CMD yarn node .