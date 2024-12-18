from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import os

SUBSCRIBERS_FILE = 'subscribers.txt'

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_message = (
        "👋 Welcome to HacktivityOne Bot!\n\n"
        "I'll notify you about new public reports on HackerOne!\n\n"
        "Commands:\n"
        "/subscribe - Start receiving notifications\n"
        "/unsubscribe - Stop receiving notifications"
    )
    await update.message.reply_text(welcome_message)

async def subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    
    subscribers = set()
    if os.path.exists(SUBSCRIBERS_FILE):
        with open(SUBSCRIBERS_FILE, 'r') as f:
            subscribers = set(int(line.strip()) for line in f if line.strip())
    
    if chat_id in subscribers:
        await update.message.reply_text("You're already subscribed!")
    else:
        subscribers.add(chat_id)
        with open(SUBSCRIBERS_FILE, 'w') as f:
            for subscriber in subscribers:
                f.write(f"{subscriber}\n")
        await update.message.reply_text("You've successfully subscribed to hacktivity notifications! 🎉")

async def unsubscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    
    subscribers = set()
    if os.path.exists(SUBSCRIBERS_FILE):
        with open(SUBSCRIBERS_FILE, 'r') as f:
            subscribers = set(int(line.strip()) for line in f if line.strip())
    
    if chat_id in subscribers:
        subscribers.remove(chat_id)
        with open(SUBSCRIBERS_FILE, 'w') as f:
            for subscriber in subscribers:
                f.write(f"{subscriber}\n")
        await update.message.reply_text("You've been unsubscribed. You can subscribe again anytime!")
    else:
        await update.message.reply_text("You're not currently subscribed.")

async def main():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable is required")

    application = Application.builder().token(bot_token).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("subscribe", subscribe))
    application.add_handler(CommandHandler("unsubscribe", unsubscribe))

    await application.run_polling()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main()) 
