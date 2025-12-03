import { WebhookPayload } from '../types';
import { Logger } from '../logger';

export class WebhookNotifier {
  private url: string;
  private events: Set<string>;
  private includePayload: boolean;
  private customHeaders: Record<string, string>;
  private logger: Logger;
  private queue: WebhookPayload[] = [];
  private processing: boolean = false;

  constructor(
    url: string,
    events: string[] = ['all'],
    includePayload: boolean = false,
    customHeaders: Record<string, string> = {},
    logger: Logger
  ) {
    this.url = url;
    this.events = new Set(events.includes('all') ? ['block', 'threat', 'rateLimit'] : events);
    this.includePayload = includePayload;
    this.customHeaders = customHeaders;
    this.logger = logger;
  }

  async notify(payload: WebhookPayload): Promise<void> {
    // Check if event should be sent
    if (!this.events.has(payload.event)) {
      return;
    }

    // Remove payload if not configured to include
    if (!this.includePayload) {
      payload = { ...payload, payload: undefined };
    }

    // Add to queue
    this.queue.push(payload);

    // Process queue
    if (!this.processing) {
      this.processQueue();
    }
  }

  private async processQueue(): Promise<void> {
    this.processing = true;

    while (this.queue.length > 0) {
      const payload = this.queue.shift()!;
      
      try {
        await this.sendWebhook(payload);
      } catch (error) {
        this.logger.error('Webhook delivery failed:', error);
        
        // Retry once after 5 seconds
        setTimeout(async () => {
          try {
            await this.sendWebhook(payload);
          } catch (retryError) {
            this.logger.error('Webhook retry failed:', retryError);
          }
        }, 5000);
      }

      // Rate limit: 1 webhook per 100ms
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.processing = false;
  }

  private async sendWebhook(payload: WebhookPayload): Promise<void> {
    const body = JSON.stringify({
      ...payload,
      source: 'Aimless Security',
      version: '1.3.4'
    });

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Aimless-Security/1.3.4',
      ...this.customHeaders
    };

    // Detect webhook type and format accordingly
    if (this.url.includes('slack.com')) {
      await this.sendSlackWebhook(payload);
    } else if (this.url.includes('discord.com')) {
      await this.sendDiscordWebhook(payload);
    } else {
      // Generic webhook
      const response = await fetch(this.url, {
        method: 'POST',
        headers,
        body
      });

      if (!response.ok) {
        throw new Error(`Webhook failed: ${response.status} ${response.statusText}`);
      }
    }
  }

  private async sendSlackWebhook(payload: WebhookPayload): Promise<void> {
    const color = payload.event === 'block' ? '#dc2626' : 
                  payload.event === 'rateLimit' ? '#f59e0b' : '#ef4444';
    
    const emoji = payload.event === 'block' ? '🛡️' : 
                  payload.event === 'rateLimit' ? '⚠️' : '🚨';

    const text = payload.event === 'block' 
      ? `*Security Threat Blocked*`
      : payload.event === 'rateLimit'
      ? `*Rate Limit Exceeded*`
      : `*Security Threat Detected*`;

    const slackPayload = {
      attachments: [{
        color,
        title: `${emoji} ${text}`,
        fields: [
          { title: 'IP Address', value: payload.ip, short: true },
          { title: 'Path', value: payload.path, short: true },
          { title: 'Method', value: payload.method, short: true },
          { title: 'Timestamp', value: payload.timestamp.toISOString(), short: true },
          ...(payload.threats && payload.threats.length > 0 ? [{
            title: 'Threats',
            value: payload.threats.map(t => 
              `• ${t.type} (${t.severity})`
            ).join('\n'),
            short: false
          }] : []),
          ...(payload.reputation !== undefined ? [{
            title: 'IP Reputation',
            value: `${payload.reputation}/100`,
            short: true
          }] : [])
        ],
        footer: 'Aimless Security',
        ts: Math.floor(payload.timestamp.getTime() / 1000)
      }]
    };

    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(slackPayload)
    });

    if (!response.ok) {
      throw new Error(`Slack webhook failed: ${response.status}`);
    }
  }

  private async sendDiscordWebhook(payload: WebhookPayload): Promise<void> {
    const color = payload.event === 'block' ? 0xdc2626 : 
                  payload.event === 'rateLimit' ? 0xf59e0b : 0xef4444;

    const title = payload.event === 'block' 
      ? '🛡️ Security Threat Blocked'
      : payload.event === 'rateLimit'
      ? '⚠️ Rate Limit Exceeded'
      : '🚨 Security Threat Detected';

    const discordPayload = {
      embeds: [{
        title,
        color,
        fields: [
          { name: 'IP Address', value: payload.ip, inline: true },
          { name: 'Path', value: payload.path, inline: true },
          { name: 'Method', value: payload.method, inline: true },
          { name: 'Timestamp', value: payload.timestamp.toISOString(), inline: true },
          ...(payload.threats && payload.threats.length > 0 ? [{
            name: 'Threats',
            value: payload.threats.map(t => 
              `• ${t.type} (${t.severity})`
            ).join('\n'),
            inline: false
          }] : []),
          ...(payload.reputation !== undefined ? [{
            name: 'IP Reputation',
            value: `${payload.reputation}/100`,
            inline: true
          }] : [])
        ],
        footer: {
          text: 'Aimless Security v1.3.4'
        },
        timestamp: payload.timestamp.toISOString()
      }]
    };

    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(discordPayload)
    });

    if (!response.ok) {
      throw new Error(`Discord webhook failed: ${response.status}`);
    }
  }
}
