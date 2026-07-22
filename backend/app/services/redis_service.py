from app.core.redis import redis_client


class RedisService:

    async def set(self, key: str, value: str, ttl: int) -> None:
        await redis_client.set(
            name=key,
            value=value,
            ex=ttl,
        )

    async def get(self, key: str) -> str | None:
        return await redis_client.get(key)

    async def delete(self, key: str) -> None:
        await redis_client.delete(key)

    async def exists(self, key: str) -> bool:
        return bool(await redis_client.exists(key))