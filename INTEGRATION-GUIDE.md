# Aimless Security - Integration Guide for All Platforms

Complete integration instructions for every type of website and platform.

---

## Table of Contents

1. [Express.js (Node.js)](#expressjs-nodejs)
2. [Next.js (Vercel/Serverless)](#nextjs-vercelserverless)
3. [React + Node.js Backend](#react--nodejs-backend)
4. [Vue.js + Express](#vuejs--express)
5. [Vanilla HTML/JavaScript + API](#vanilla-htmljavascript--api)
6. [NestJS](#nestjs)
7. [Fastify](#fastify)
8. [Koa](#koa)
9. [Hapi](#hapi)
10. [AWS Lambda](#aws-lambda)
11. [Netlify Functions](#netlify-functions)
12. [Cloudflare Workers](#cloudflare-workers)
13. [Nuxt.js](#nuxtjs)
14. [Remix](#remix)
15. [SvelteKit](#sveltekit)
16. [Astro](#astro)
17. [Django REST API (Python + Node proxy)](#django-rest-api)
18. [GraphQL Server](#graphql-server)

---

## Express.js (Node.js)

### Installation
```bash
npm install aimless-security
```

### Basic Setup
```javascript
// server.js
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

// Initialize Aimless
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false, // Start with detection mode
    trustedOrigins: ['http://localhost:3000']
  }
});

// Apply middleware globally
app.use(aimless.middleware());

// Protected routes
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  
  if (!aimless.isSafe(message)) {
    return res.status(400).json({ error: 'Invalid input detected' });
  }
  
  // Process safely
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Advanced Setup with CSRF
```javascript
const { Aimless } = require('aimless-security');

const { middleware, csrf, aimless } = Aimless.quickProtect([
  'http://localhost:3000',
  'https://yourdomain.com'
]);

app.use(middleware);

// Get CSRF token
app.get('/api/csrf-token', (req, res) => {
  const token = csrf.generateToken(req.session.id);
  res.json({ csrfToken: token });
});

// Validate CSRF on POST
app.post('/api/submit', (req, res) => {
  const isValid = csrf.validateToken(
    req.body.csrfToken,
    req.session.id
  );
  
  if (!isValid) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  // Process request
});
```

---

## Next.js (Vercel/Serverless)

### Installation
```bash
npm install aimless-security
```

### Step 1: Configure `next.config.js`
```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['aimless-security']
  }
}

module.exports = nextConfig
```

### Step 2: Create Security Helper (`lib/security.ts`)
```typescript
import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false,
    trustedOrigins: [
      process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'
    ]
  }
});

export function validateInput(input: string): boolean {
  try {
    return aimless.isSafe(input);
  } catch (error) {
    console.error('Validation error:', error);
    return true; // Fail open
  }
}

export function sanitize(input: string, context: 'html' | 'javascript' | 'url' | 'sql' = 'html'): string {
  try {
    return aimless.sanitizeFor(input, context);
  } catch (error) {
    return input;
  }
}

export { aimless };
```

### Step 3: API Route (`app/api/contact/route.ts`)
```typescript
// CRITICAL: This line is required for Vercel!
export const runtime = 'nodejs';

import { NextRequest, NextResponse } from 'next/server';
import { validateInput, sanitize } from '@/lib/security';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, email, message } = body;
    
    // Validate input
    if (!validateInput(message)) {
      return NextResponse.json(
        { error: 'Invalid input detected' },
        { status: 400 }
      );
    }
    
    // Sanitize before storing
    const cleanMessage = sanitize(message, 'html');
    
    // Store in database
    await saveToDatabase({ name, email, message: cleanMessage });
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('API Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

### Step 4: Server Actions (`app/actions.ts`)
```typescript
'use server';

import { validateInput, sanitize } from '@/lib/security';

export async function submitForm(formData: FormData) {
  const message = formData.get('message') as string;
  
  if (!validateInput(message)) {
    return { success: false, error: 'Invalid input' };
  }
  
  const clean = sanitize(message, 'html');
  await saveToDatabase({ message: clean });
  
  return { success: true };
}
```

### Step 5: Client Component (`components/ContactForm.tsx`)
```typescript
'use client';

import { submitForm } from '@/app/actions';

export default function ContactForm() {
  async function handleSubmit(formData: FormData) {
    const result = await submitForm(formData);
    
    if (!result.success) {
      alert(result.error);
    } else {
      alert('Form submitted!');
    }
  }
  
  return (
    <form action={handleSubmit}>
      <textarea name="message" required />
      <button type="submit">Submit</button>
    </form>
  );
}
```

---

## React + Node.js Backend

### Backend Setup (`server/index.js`)
```javascript
const express = require('express');
const cors = require('cors');
const { Aimless } = require('aimless-security');

const app = express();
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());

const aimless = new Aimless({
  rasp: {
    enabled: true,
    trustedOrigins: ['http://localhost:3000']
  }
});

app.use(aimless.middleware());

app.post('/api/data', (req, res) => {
  if (!aimless.isSafe(req.body.input)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  res.json({ success: true });
});

app.listen(5000);
```

### React Frontend (`src/App.jsx`)
```javascript
import { useState } from 'react';

function App() {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      const response = await fetch('http://localhost:5000/api/data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error);
      } else {
        alert('Success!');
      }
    } catch (err) {
      setError('Network error');
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <button type="submit">Submit</button>
    </form>
  );
}

export default App;
```

---

## Vue.js + Express

### Backend (`server.js`)
```javascript
const express = require('express');
const cors = require('cors');
const { Aimless } = require('aimless-security');

const app = express();
app.use(cors());
app.use(express.json());

const aimless = new Aimless({
  rasp: { enabled: true }
});

app.use(aimless.middleware());

app.post('/api/submit', (req, res) => {
  if (!aimless.isSafe(req.body.data)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  res.json({ success: true });
});

app.listen(3000);
```

### Vue Component (`ContactForm.vue`)
```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input v-model="message" />
    <p v-if="error" class="error">{{ error }}</p>
    <button type="submit">Submit</button>
  </form>
</template>

<script>
export default {
  data() {
    return {
      message: '',
      error: ''
    };
  },
  methods: {
    async handleSubmit() {
      try {
        const response = await fetch('http://localhost:3000/api/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: this.message })
        });
        
        const result = await response.json();
        
        if (!response.ok) {
          this.error = result.error;
        } else {
          alert('Success!');
        }
      } catch (err) {
        this.error = 'Network error';
      }
    }
  }
};
</script>
```

---

## Vanilla HTML/JavaScript + API

### Backend (`server.js`)
```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const aimless = new Aimless({
  rasp: { enabled: true }
});

app.post('/api/contact', (req, res) => {
  if (!aimless.isSafe(req.body.message)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  res.json({ success: true });
});

app.listen(3000);
```

### Frontend (`public/index.html`)
```html
<!DOCTYPE html>
<html>
<head>
  <title>Contact Form</title>
</head>
<body>
  <form id="contactForm">
    <input type="text" id="name" placeholder="Name" required>
    <textarea id="message" placeholder="Message" required></textarea>
    <button type="submit">Submit</button>
    <p id="error" style="color: red;"></p>
  </form>
  
  <script>
    document.getElementById('contactForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const name = document.getElementById('name').value;
      const message = document.getElementById('message').value;
      const errorEl = document.getElementById('error');
      
      try {
        const response = await fetch('/api/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, message })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
          errorEl.textContent = data.error;
        } else {
          alert('Form submitted successfully!');
          e.target.reset();
        }
      } catch (err) {
        errorEl.textContent = 'Network error';
      }
    });
  </script>
</body>
</html>
```

---

## NestJS

### Installation
```bash
npm install aimless-security
```

### Create Middleware (`src/aimless.middleware.ts`)
```typescript
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { Aimless } from 'aimless-security';

@Injectable()
export class AimlessMiddleware implements NestMiddleware {
  private aimless: Aimless;
  
  constructor() {
    this.aimless = new Aimless({
      rasp: {
        enabled: true,
        blockMode: false
      }
    });
  }
  
  use(req: Request, res: Response, next: NextFunction) {
    const middleware = this.aimless.middleware();
    middleware(req, res, next);
  }
}
```

### Apply Middleware (`src/app.module.ts`)
```typescript
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { AimlessMiddleware } from './aimless.middleware';

@Module({
  // ...
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AimlessMiddleware)
      .forRoutes('*');
  }
}
```

### Use in Controller (`src/contact/contact.controller.ts`)
```typescript
import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { Aimless } from 'aimless-security';

@Controller('contact')
export class ContactController {
  private aimless = new Aimless();
  
  @Post()
  submitContact(@Body() body: { message: string }) {
    if (!this.aimless.isSafe(body.message)) {
      throw new BadRequestException('Invalid input detected');
    }
    
    return { success: true };
  }
}
```

---

## Fastify

### Installation
```bash
npm install aimless-security
```

### Setup (`server.js`)
```javascript
const fastify = require('fastify')();
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: { enabled: true }
});

// Register as hook
fastify.addHook('preHandler', (request, reply, done) => {
  // Validate input
  if (request.body) {
    const bodyStr = JSON.stringify(request.body);
    if (!aimless.isSafe(bodyStr)) {
      reply.code(400).send({ error: 'Invalid input' });
      return;
    }
  }
  done();
});

fastify.post('/api/contact', async (request, reply) => {
  const { message } = request.body;
  
  if (!aimless.isSafe(message)) {
    return reply.code(400).send({ error: 'Invalid input' });
  }
  
  return { success: true };
});

fastify.listen({ port: 3000 }, (err) => {
  if (err) throw err;
  console.log('Server running on port 3000');
});
```

---

## Koa

### Installation
```bash
npm install aimless-security koa koa-bodyparser
```

### Setup (`server.js`)
```javascript
const Koa = require('koa');
const bodyParser = require('koa-bodyparser');
const { Aimless } = require('aimless-security');

const app = new Koa();
app.use(bodyParser());

const aimless = new Aimless({
  rasp: { enabled: true }
});

// Middleware
app.use(async (ctx, next) => {
  if (ctx.request.body) {
    const bodyStr = JSON.stringify(ctx.request.body);
    if (!aimless.isSafe(bodyStr)) {
      ctx.status = 400;
      ctx.body = { error: 'Invalid input' };
      return;
    }
  }
  await next();
});

// Routes
app.use(async (ctx) => {
  if (ctx.method === 'POST' && ctx.path === '/api/contact') {
    const { message } = ctx.request.body;
    
    if (!aimless.isSafe(message)) {
      ctx.status = 400;
      ctx.body = { error: 'Invalid input' };
      return;
    }
    
    ctx.body = { success: true };
  }
});

app.listen(3000);
```

---

## Hapi

### Installation
```bash
npm install aimless-security @hapi/hapi
```

### Setup (`server.js`)
```javascript
const Hapi = require('@hapi/hapi');
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: { enabled: true }
});

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: 'localhost'
  });
  
  // Extension point for validation
  server.ext('onPreHandler', (request, h) => {
    if (request.payload) {
      const payloadStr = JSON.stringify(request.payload);
      if (!aimless.isSafe(payloadStr)) {
        return h.response({ error: 'Invalid input' }).code(400).takeover();
      }
    }
    return h.continue;
  });
  
  server.route({
    method: 'POST',
    path: '/api/contact',
    handler: (request, h) => {
      const { message } = request.payload;
      
      if (!aimless.isSafe(message)) {
        return h.response({ error: 'Invalid input' }).code(400);
      }
      
      return { success: true };
    }
  });
  
  await server.start();
  console.log('Server running on %s', server.info.uri);
};

init();
```

---

## AWS Lambda

### Installation
```bash
npm install aimless-security
```

### Lambda Function (`handler.js`)
```javascript
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false
  }
});

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    
    // Validate input
    if (!aimless.isSafe(body.message)) {
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Invalid input detected' })
      };
    }
    
    // Process request
    const result = await processData(body);
    
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, data: result })
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};

async function processData(data) {
  // Your business logic
  return { processed: true };
}
```

### Deploy with SAM (`template.yaml`)
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  ContactFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handler.handler
      Runtime: nodejs20.x
      Events:
        ContactAPI:
          Type: Api
          Properties:
            Path: /contact
            Method: post
```

---

## Netlify Functions

### Installation
```bash
npm install aimless-security
```

### Function (`netlify/functions/contact.js`)
```javascript
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

exports.handler = async (event, context) => {
  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }
  
  try {
    const body = JSON.parse(event.body);
    
    // Validate input
    if (!aimless.isSafe(body.message)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid input detected' })
      };
    }
    
    // Process request
    await saveToDatabase(body);
    
    return {
      statusCode: 200,
      body: JSON.stringify({ success: true })
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
```

### Frontend Call
```javascript
async function submitForm(data) {
  const response = await fetch('/.netlify/functions/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  
  return response.json();
}
```

---

## Cloudflare Workers

### Note
Cloudflare Workers use V8 isolates (not Node.js), so Aimless Security's Node.js crypto module won't work directly. Use a proxy pattern:

### Setup API on Node.js (Vercel/AWS)
```javascript
// Deploy this on Vercel or AWS Lambda
const { Aimless } = require('aimless-security');
const express = require('express');

const app = express();
app.use(express.json());

const aimless = new Aimless();

app.post('/validate', (req, res) => {
  const safe = aimless.isSafe(req.body.input);
  res.json({ safe });
});

module.exports = app;
```

### Cloudflare Worker
```javascript
export default {
  async fetch(request) {
    if (request.method === 'POST') {
      const body = await request.json();
      
      // Call validation API
      const validationResponse = await fetch('https://your-api.vercel.app/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: body.message })
      });
      
      const { safe } = await validationResponse.json();
      
      if (!safe) {
        return new Response(
          JSON.stringify({ error: 'Invalid input' }),
          { status: 400 }
        );
      }
      
      // Process request
      return new Response(JSON.stringify({ success: true }));
    }
  }
};
```

---

## Nuxt.js

### Installation
```bash
npm install aimless-security
```

### Server Middleware (`server/middleware/aimless.js`)
```javascript
import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

export default defineEventHandler((event) => {
  // Skip for static assets
  if (event.path.startsWith('/_nuxt/')) {
    return;
  }
  
  // Validate POST requests
  if (event.method === 'POST') {
    const body = getRequestBody(event);
    const bodyStr = JSON.stringify(body);
    
    if (!aimless.isSafe(bodyStr)) {
      throw createError({
        statusCode: 400,
        message: 'Invalid input detected'
      });
    }
  }
});
```

### API Route (`server/api/contact.post.js`)
```javascript
import { Aimless } from 'aimless-security';

const aimless = new Aimless();

export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  
  if (!aimless.isSafe(body.message)) {
    throw createError({
      statusCode: 400,
      message: 'Invalid input'
    });
  }
  
  // Process
  return { success: true };
});
```

### Component Usage (`pages/contact.vue`)
```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input v-model="message" />
    <button type="submit">Submit</button>
  </form>
</template>

<script setup>
const message = ref('');

async function handleSubmit() {
  try {
    await $fetch('/api/contact', {
      method: 'POST',
      body: { message: message.value }
    });
    
    alert('Success!');
  } catch (error) {
    alert(error.data.message);
  }
}
</script>
```

---

## Remix

### Installation
```bash
npm install aimless-security
```

### Utility (`app/utils/security.server.ts`)
```typescript
import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

export function validateInput(input: string): boolean {
  try {
    return aimless.isSafe(input);
  } catch {
    return true; // Fail open
  }
}

export function sanitize(input: string): string {
  return aimless.sanitizeFor(input, 'html');
}
```

### Route with Action (`app/routes/contact.tsx`)
```typescript
import type { ActionFunctionArgs } from '@remix-run/node';
import { json } from '@remix-run/node';
import { Form, useActionData } from '@remix-run/react';
import { validateInput, sanitize } from '~/utils/security.server';

export async function action({ request }: ActionFunctionArgs) {
  const formData = await request.formData();
  const message = formData.get('message') as string;
  
  if (!validateInput(message)) {
    return json(
      { error: 'Invalid input detected' },
      { status: 400 }
    );
  }
  
  const clean = sanitize(message);
  await saveToDatabase({ message: clean });
  
  return json({ success: true });
}

export default function Contact() {
  const actionData = useActionData<typeof action>();
  
  return (
    <Form method="post">
      <textarea name="message" required />
      {actionData?.error && <p>{actionData.error}</p>}
      <button type="submit">Submit</button>
    </Form>
  );
}
```

---

## SvelteKit

### Installation
```bash
npm install aimless-security
```

### Utility (`src/lib/server/security.ts`)
```typescript
import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

export function validateInput(input: string): boolean {
  try {
    return aimless.isSafe(input);
  } catch {
    return true;
  }
}
```

### API Route (`src/routes/api/contact/+server.ts`)
```typescript
import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { validateInput } from '$lib/server/security';

export const POST: RequestHandler = async ({ request }) => {
  const body = await request.json();
  
  if (!validateInput(body.message)) {
    return json(
      { error: 'Invalid input detected' },
      { status: 400 }
    );
  }
  
  // Process
  return json({ success: true });
};
```

### Page with Form (`src/routes/contact/+page.svelte`)
```svelte
<script>
  let message = '';
  let error = '';
  
  async function handleSubmit() {
    const response = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      error = data.error;
    } else {
      alert('Success!');
    }
  }
</script>

<form on:submit|preventDefault={handleSubmit}>
  <textarea bind:value={message} required />
  {#if error}
    <p class="error">{error}</p>
  {/if}
  <button type="submit">Submit</button>
</form>
```

---

## Astro

### Installation
```bash
npm install aimless-security
```

### API Endpoint (`src/pages/api/contact.ts`)
```typescript
import type { APIRoute } from 'astro';
import { Aimless } from 'aimless-security';

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    
    if (!aimless.isSafe(body.message)) {
      return new Response(
        JSON.stringify({ error: 'Invalid input detected' }),
        { status: 400 }
      );
    }
    
    // Process request
    return new Response(
      JSON.stringify({ success: true }),
      { status: 200 }
    );
  } catch (error) {
    return new Response(
      JSON.stringify({ error: 'Server error' }),
      { status: 500 }
    );
  }
};
```

### Page with Form (`src/pages/contact.astro`)
```astro
---
// Server-side code
---

<html>
  <body>
    <form id="contactForm">
      <textarea id="message" required></textarea>
      <button type="submit">Submit</button>
      <p id="error"></p>
    </form>
    
    <script>
      document.getElementById('contactForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const message = document.getElementById('message').value;
        const errorEl = document.getElementById('error');
        
        try {
          const response = await fetch('/api/contact', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
          });
          
          const data = await response.json();
          
          if (!response.ok) {
            errorEl.textContent = data.error;
          } else {
            alert('Success!');
          }
        } catch (err) {
          errorEl.textContent = 'Network error';
        }
      });
    </script>
  </body>
</html>
```

---

## Django REST API

Since Django is Python, you'll need a Node.js proxy or microservice:

### Node.js Validation Service (`validation-service.js`)
```javascript
const express = require('express');
const { Aimless } = require('aimless-security');

const app = express();
app.use(express.json());

const aimless = new Aimless();

app.post('/validate', (req, res) => {
  const safe = aimless.isSafe(req.body.input);
  const sanitized = aimless.sanitizeFor(req.body.input, 'html');
  
  res.json({ safe, sanitized });
});

app.listen(3001, () => {
  console.log('Validation service on port 3001');
});
```

### Django View (`views.py`)
```python
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['POST'])
def contact_view(request):
    message = request.data.get('message')
    
    # Call Node.js validation service
    validation_response = requests.post(
        'http://localhost:3001/validate',
        json={'input': message}
    )
    
    validation = validation_response.json()
    
    if not validation['safe']:
        return Response(
            {'error': 'Invalid input detected'},
            status=400
        )
    
    # Use sanitized version
    clean_message = validation['sanitized']
    
    # Save to database
    return Response({'success': True})
```

---

## GraphQL Server

### Installation
```bash
npm install aimless-security apollo-server-express
```

### Setup (`server.js`)
```javascript
const express = require('express');
const { ApolloServer } = require('apollo-server-express');
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: { enabled: true, blockMode: false }
});

const typeDefs = `
  type Query {
    hello: String
  }
  
  type Mutation {
    submitContact(name: String!, message: String!): Response
  }
  
  type Response {
    success: Boolean
    error: String
  }
`;

const resolvers = {
  Mutation: {
    submitContact: async (_, { name, message }) => {
      // Validate inputs
      if (!aimless.isSafe(name) || !aimless.isSafe(message)) {
        return {
          success: false,
          error: 'Invalid input detected'
        };
      }
      
      // Process
      return { success: true };
    }
  }
};

async function startServer() {
  const app = express();
  
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: ({ req }) => ({ req })
  });
  
  await server.start();
  server.applyMiddleware({ app });
  
  app.listen(4000, () => {
    console.log('GraphQL server on http://localhost:4000/graphql');
  });
}

startServer();
```

---

## Common Patterns Across All Platforms

### Pattern 1: Fail-Open Error Handling
```javascript
function safeValidate(input) {
  try {
    return aimless.isSafe(input);
  } catch (error) {
    console.error('Validation error:', error);
    return true; // Allow request if validation fails
  }
}
```

### Pattern 2: Sanitize Instead of Block
```javascript
// Instead of blocking, sanitize
const clean = aimless.sanitizeFor(userInput, 'html');
await saveToDatabase({ message: clean });
```

### Pattern 3: IP Reputation Check
```javascript
const score = aimless.getIPReputation(req.ip);
if (score < 30) {
  // High-risk IP - extra validation
  if (!aimless.isSafe(req.body.message)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
}
```

### Pattern 4: Selective Protection
```javascript
// Only protect specific routes
app.post('/api/public/contact', aimless.middleware());
app.post('/api/public/search', aimless.middleware());

// Don't protect webhook endpoints
app.post('/webhooks/stripe', stripeWebhook);
```

---

## Deployment Checklist

- [ ] Install: `npm install aimless-security`
- [ ] Configure with `blockMode: false` initially
- [ ] Add `trustedOrigins` for your domain
- [ ] Wrap validation in try-catch
- [ ] Test with malicious inputs
- [ ] Monitor logs for false positives
- [ ] Gradually enable `blockMode: true`
- [ ] Set up alerts for threats

---

## Testing Your Integration

### Test SQL Injection
```bash
curl -X POST http://localhost:3000/api/test \
  -H "Content-Type: application/json" \
  -d '{"input": "'"'"' OR 1=1--"}'
```

### Test XSS
```bash
curl -X POST http://localhost:3000/api/test \
  -H "Content-Type: application/json" \
  -d '{"input": "<script>alert(1)</script>"}'
```

### Test Normal Input
```bash
curl -X POST http://localhost:3000/api/test \
  -H "Content-Type: application/json" \
  -d '{"input": "Hello, World!"}'
```

---

## Support & Resources

- **GitHub**: [Report Issues](https://github.com/CamozDevelopment/Aimless-Security)
- **Docs**: `README.md`, `VERCEL.md`, `QUICK-REFERENCE.md`
- **Examples**: `/examples` directory in package

---

*Last Updated: November 19, 2025*
