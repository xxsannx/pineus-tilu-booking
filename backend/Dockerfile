FROM node:20-bullseye

# Set working directory
WORKDIR /app

# Copy package.json dan package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy seluruh kode backend
COPY . .

# Set environment
ENV NODE_ENV=production

# Expose port backend
EXPOSE 3000

# Jalankan server
CMD ["node", "server.js"]
