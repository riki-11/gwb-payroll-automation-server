#!/bin/bash
echo "Installing Yarn globally..."
npm install -g yarn

echo "Installing dependencies with Yarn..."
yarn install

echo "Building TypeScript with Yarn..."
yarn build
