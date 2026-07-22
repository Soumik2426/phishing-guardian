import random

from fastapi import logger

from app.services.redis_service import RedisService


class OTPService:

    OTP_LENGTH = 6
    OTP_EXPIRATION = 300  # 5 minutes

    def __init__(self):
        self.redis_service = RedisService()

    def generate_otp(self) -> str:
        return "".join(
            random.choices("0123456789", k=self.OTP_LENGTH)
        )

    def get_key(self, email: str) -> str:
        return f"email_verification:{email}"

    async def create_otp(self, email: str) -> str:
        otp = self.generate_otp()

        logger.info(f"OTP generated for {email}")

        await self.redis_service.set(
            key=self.get_key(email),
            value=otp,
            ttl=self.OTP_EXPIRATION,
        )
        logger.info(f"OTP stored in redis for {email}")
        return otp

    async def verify_otp(
        self,
        email: str,
        otp: str,
    ) -> bool:

        stored_otp = await self.redis_service.get(
            self.get_key(email)
        )

        return stored_otp == otp

    async def delete_otp(self, email: str):
        await self.redis_service.delete(
            self.get_key(email)
        )