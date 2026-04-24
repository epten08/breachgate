import { AIError } from "../core/errors.js";
import { logger } from "../core/logger.js";

export type AIProvider = "ollama" | "openai" | "anthropic";

export interface AIConfig {
  provider: AIProvider;
  model: string;
  baseUrl?: string;
  apiKey?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AIResponse {
  content: string;
  model: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
  };
}

export class AIClient {
  private config: AIConfig;

  constructor(config: AIConfig) {
    this.config = {
      temperature: 0.7,
      maxTokens: 2048,
      ...config,
    };
  }

  async chat(messages: ChatMessage[]): Promise<AIResponse> {
    switch (this.config.provider) {
      case "ollama":
        return this.chatOllama(messages);
      case "openai":
        return this.chatOpenAI(messages);
      case "anthropic":
        return this.chatAnthropic(messages);
      default:
        throw new AIError(`Unsupported AI provider: ${this.config.provider}`);
    }
  }

  async generate(prompt: string, systemPrompt?: string): Promise<string> {
    const messages: ChatMessage[] = [];

    if (systemPrompt) {
      messages.push({ role: "system", content: systemPrompt });
    }

    messages.push({ role: "user", content: prompt });

    const response = await this.chat(messages);
    return response.content;
  }

  private async chatOllama(messages: ChatMessage[]): Promise<AIResponse> {
    const baseUrl = this.config.baseUrl || "http://localhost:11434";

    try {
      const response = await fetch(`${baseUrl}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: this.config.model,
          messages: messages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          stream: false,
          options: {
            temperature: this.config.temperature,
            num_predict: this.config.maxTokens,
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status}`);
      }

      const data = await response.json() as {
        message: { content: string };
        model: string;
        prompt_eval_count?: number;
        eval_count?: number;
      };

      return {
        content: data.message.content,
        model: data.model,
        usage: {
          promptTokens: data.prompt_eval_count || 0,
          completionTokens: data.eval_count || 0,
        },
      };
    } catch (err) {
      logger.debug(`Ollama request failed: ${(err as Error).message}`);
      throw new AIError(`Ollama API error: ${(err as Error).message}`, err as Error);
    }
  }

  private async chatOpenAI(messages: ChatMessage[]): Promise<AIResponse> {
    const baseUrl = this.config.baseUrl || "https://api.openai.com/v1";
    const apiKey = this.config.apiKey || process.env.OPENAI_API_KEY;

    if (!apiKey) {
      throw new AIError("OpenAI API key not configured");
    }

    try {
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: this.config.model,
          messages,
          temperature: this.config.temperature,
          max_tokens: this.config.maxTokens,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`OpenAI API error: ${response.status} - ${error}`);
      }

      const data = await response.json() as {
        choices: { message: { content: string } }[];
        model: string;
        usage: { prompt_tokens: number; completion_tokens: number };
      };

      return {
        content: data.choices[0].message.content,
        model: data.model,
        usage: {
          promptTokens: data.usage.prompt_tokens,
          completionTokens: data.usage.completion_tokens,
        },
      };
    } catch (err) {
      logger.debug(`OpenAI request failed: ${(err as Error).message}`);
      throw new AIError(`OpenAI API error: ${(err as Error).message}`, err as Error);
    }
  }

  private async chatAnthropic(messages: ChatMessage[]): Promise<AIResponse> {
    const baseUrl = this.config.baseUrl || "https://api.anthropic.com";
    const apiKey = this.config.apiKey || process.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      throw new AIError("Anthropic API key not configured");
    }

    // Extract system message
    const systemMessage = messages.find((m) => m.role === "system");
    const chatMessages = messages.filter((m) => m.role !== "system");

    try {
      const response = await fetch(`${baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: this.config.model,
          max_tokens: this.config.maxTokens,
          system: systemMessage?.content,
          messages: chatMessages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Anthropic API error: ${response.status} - ${error}`);
      }

      const data = await response.json() as {
        content: { text: string }[];
        model: string;
        usage: { input_tokens: number; output_tokens: number };
      };

      return {
        content: data.content[0].text,
        model: data.model,
        usage: {
          promptTokens: data.usage.input_tokens,
          completionTokens: data.usage.output_tokens,
        },
      };
    } catch (err) {
      logger.debug(`Anthropic request failed: ${(err as Error).message}`);
      throw new AIError(`Anthropic API error: ${(err as Error).message}`, err as Error);
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      if (this.config.provider === "ollama") {
        const baseUrl = this.config.baseUrl || "http://localhost:11434";
        const response = await fetch(`${baseUrl}/api/tags`);
        return response.ok;
      }

      // For cloud providers, check if API key is set
      if (this.config.provider === "openai") {
        return !!(this.config.apiKey || process.env.OPENAI_API_KEY);
      }

      if (this.config.provider === "anthropic") {
        return !!(this.config.apiKey || process.env.ANTHROPIC_API_KEY);
      }

      return false;
    } catch {
      return false;
    }
  }
}
