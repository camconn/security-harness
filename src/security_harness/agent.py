from typing import Literal

from langchain.agents import create_agent
from langchain_anthropic import ChatAnthropic
from langchain_anthropic.middleware import AnthropicPromptCachingMiddleware
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI

Provider = Literal["openai", "anthropic"]


def make_llm(provider: Provider, model: str | None = None, **kwargs) -> BaseChatModel:
    match provider:
        case "openai":
            resolved_model = model or "gpt-5.4"
            if resolved_model == "gpt-5.4":
                kwargs.setdefault("reasoning", {"effort": "medium"})
            return ChatOpenAI(model=resolved_model, **kwargs)
        case "anthropic":
            return ChatAnthropic(model=model or "claude-sonnet-4-6", **kwargs)
        case _:
            raise ValueError(f"Unsupported provider: {provider!r}")


def make_analysis_agent(llm: BaseChatModel, tools: list[BaseTool]):
    middleware = [AnthropicPromptCachingMiddleware()] if isinstance(llm, ChatAnthropic) else []
    return create_agent(llm, tools, middleware=middleware)
