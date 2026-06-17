# RedCalibur web console — Next.js operator console.
FROM node:20-slim AS build

WORKDIR /app
COPY package.json package-lock.json* /app/
COPY apps/web/package.json /app/apps/web/package.json
RUN npm install
COPY apps/web /app/apps/web
ARG NEXT_PUBLIC_API_BASE=http://localhost:8000
ENV NEXT_PUBLIC_API_BASE=$NEXT_PUBLIC_API_BASE
RUN npm --workspace apps/web run build

FROM node:20-slim AS run
WORKDIR /app
COPY --from=build /app /app
ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "--workspace", "apps/web", "run", "start"]
