from pathlib import Path

from fastapi import logger
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from jinja2 import Environment, FileSystemLoader

from app.core.config import settings


class EmailService:
    def __init__(self):
        self.conf = ConnectionConfig(
            MAIL_USERNAME=settings.MAIL_USERNAME,
            MAIL_PASSWORD=settings.MAIL_PASSWORD,
            MAIL_FROM=settings.MAIL_FROM,
            MAIL_PORT=settings.MAIL_PORT,
            MAIL_SERVER=settings.MAIL_SERVER,
            MAIL_STARTTLS=settings.MAIL_STARTTLS,
            MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
            MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True,
        )

        template_path = Path(__file__).parent.parent / "templates"

        self.environment = Environment(
            loader=FileSystemLoader(template_path)
        )

    async def send_email(
            self,
            recipient: str,
            subject: str,
            template_name: str,
            context: dict,
    ):

        template = self.environment.get_template(template_name)

        html = template.render(**context)

        message = MessageSchema(
            subject=subject,
            recipients=[recipient],
            body=html,
            subtype=MessageType.html,
        )

        fm = FastMail(self.conf)

        logger.info(f"Sending verification email to {recipient}")

        try:
            await fm.send_message(message)
            logger.info(f"Verification email sent successfully to {recipient}")
        except Exception as e:
            logger.info(f"Verification email failed to sent to {recipient}")
            print(e)
            raise