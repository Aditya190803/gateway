import { Context } from 'hono';
import {
  AllHookResults,
  HookObject,
  HookResult,
  HookSpanContext,
} from './types';

export class HookSpan {
  private context: HookSpanContext;
  private hooksResult: AllHookResults = {
    beforeRequestHooksResult: [],
    afterRequestHooksResult: [],
  };
  public readonly id: string;

  constructor(
    requestParams: Record<string, any>,
    metadata: Record<string, string>,
    provider: string,
    isStreamingRequest: boolean,
    private beforeRequestHooks: HookObject[] = [],
    private afterRequestHooks: HookObject[] = [],
    private parentHookSpanId: string | null = null,
    requestType: string,
    requestHeaders: Record<string, string>
  ) {
    this.id = crypto.randomUUID();
    this.context = {
      request: {
        json: requestParams,
        text: typeof requestParams === 'string' ? requestParams : JSON.stringify(requestParams ?? {}),
        isStreamingRequest,
        isTransformed: false,
        headers: requestHeaders,
      },
      response: {
        text: '',
        json: {},
        statusCode: null,
        isTransformed: false,
      },
      provider,
      requestType,
      metadata,
    };
  }

  public getContext(): HookSpanContext {
    return this.context;
  }

  public getBeforeRequestHooks(): HookObject[] {
    return this.beforeRequestHooks;
  }

  public getAfterRequestHooks(): HookObject[] {
    return this.afterRequestHooks;
  }

  public getParentHookSpanId(): string | null {
    return this.parentHookSpanId;
  }

  public getHooksResult(): AllHookResults {
    return this.hooksResult;
  }

  public setContextResponse(responseJson: Record<string, any>, responseStatusCode: number): void {
    this.context.response = {
      text: typeof responseJson === 'string' ? responseJson : JSON.stringify(responseJson ?? {}),
      json: responseJson,
      statusCode: responseStatusCode,
      isTransformed: false,
    };
  }

  public setContextAfterTransform(responseJson?: Record<string, any>, requestJson?: Record<string, any>): void {
    if (requestJson) {
      this.context.request.json = requestJson;
      this.context.request.text = JSON.stringify(requestJson);
      this.context.request.isTransformed = true;
    }
    if (responseJson) {
      this.context.response.json = responseJson;
      this.context.response.text = JSON.stringify(responseJson);
      this.context.response.isTransformed = true;
    }
  }

  public addHookResult(eventType: 'beforeRequestHook' | 'afterRequestHook', hookResult: HookResult): void {
    if (eventType === 'beforeRequestHook') {
      this.hooksResult.beforeRequestHooksResult.push(hookResult);
    } else {
      this.hooksResult.afterRequestHooksResult.push(hookResult);
    }
  }
}

export class HooksManager {
  private spans: Record<string, HookSpan> = {};

  public createSpan(
    requestParams: any,
    metadata: Record<string, string>,
    provider: string,
    isStreamingRequest: boolean,
    beforeRequestHooks: HookObject[],
    afterRequestHooks: HookObject[],
    parentHookSpanId: string | null,
    requestType: string,
    requestHeaders: Record<string, string>
  ): HookSpan {
    const span = new HookSpan(
      requestParams,
      metadata,
      provider,
      isStreamingRequest,
      beforeRequestHooks,
      afterRequestHooks,
      parentHookSpanId,
      requestType,
      requestHeaders
    );
    this.spans[span.id] = span;
    return span;
  }

  public getSpan(spanId: string): HookSpan {
    return this.spans[spanId];
  }

  public setSpanContextResponse(
    spanId: string,
    responseJson: Record<string, any>,
    responseStatusCode: number
  ): void {
    this.spans[spanId]?.setContextResponse(responseJson, responseStatusCode);
  }

  public async executeHooks(
    _spanId?: string,
    _eventTypePresets?: string[],
    _options?: unknown
  ): Promise<{ results: HookResult[]; shouldDeny: boolean }> {
    return { results: [], shouldDeny: false };
  }

  public getHooksToExecute(_span?: HookSpan, _eventTypePresets?: string[]): HookObject[] {
    return [];
  }
}

export const hooks = (c: Context, next: any) => {
  const hooksManager = new HooksManager();
  c.set('hooksManager', hooksManager);
  c.set('executeHooks', hooksManager.executeHooks.bind(hooksManager));
  return next();
};
