FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# 流量特征消除：随机化工作目录与环境变量
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
