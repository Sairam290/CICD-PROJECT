FROM node:18-alpine AS build
WORKDIR /app

# install deps (supports bun if lockfile present)
COPY package*.json ./
COPY bun.lockb ./
RUN if [ -f bun.lockb ]; then npm install -g bun && bun install || true; else npm ci || true; fi

# copy source and build
COPY . .
RUN if [ -f bun.lockb ]; then bun run build; else npm run build; fi

FROM nginx:stable-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx","-g","daemon off;"]
