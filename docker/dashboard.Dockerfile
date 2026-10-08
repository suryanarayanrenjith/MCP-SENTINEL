FROM node:22-alpine AS build
WORKDIR /ui
COPY dashboard/package.json ./
RUN npm install
COPY dashboard ./
ENV VITE_API_URL=
RUN npm run build

FROM nginx:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /ui/dist /usr/share/nginx/html
