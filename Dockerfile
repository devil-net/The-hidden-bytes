FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install
RUN npm install --save react react-dom @headlessui/react @heroicons/react react-dropzone
RUN npm install --save-dev @types/react @types/react-dom @types/react-dropzone

# Copy the rest of the application
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Command to run the application in development mode
CMD ["sh", "-c", "npm run dev -- --host 0.0.0.0"] 