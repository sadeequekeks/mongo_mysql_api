FROM node:stretch-slim
LABEL author="Abubakar Zubair"
WORKDIR /app
COPY package.json /app
COPY src /app
RUN ["npm", "install"]
EXPOSE 80
CMD ["npm", "start"]