# Stage 1: Build
FROM node:18-alpine AS build
ARG service
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY shared/auth ./shared/auth

# Stage 2: Production
FROM node:18-alpine AS production
ARG service
WORKDIR /usr/src/app
RUN apk update && apk upgrade --no-cache
COPY --chown=node:node --from=build /usr/src/app/shared ./shared
RUN ln -s /usr/src/app/shared /usr/src/shared
# Set non-root user
USER node
COPY --chown=node:node --from=build /usr/src/app/node_modules ./node_modules
COPY --chown=node:node --from=build /usr/src/app/src ./src
COPY --chown=node:node package.json ./

EXPOSE 3000
CMD ["npm", "start"]

