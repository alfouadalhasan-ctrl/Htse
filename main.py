import os
import re
import tldextract
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, MessageHandler, CommandHandler, CallbackQueryHandler, filters, ContextTypes
from telegram.error import BadRequest, Forbidden
from telegram.constants import ParseMode

TOKEN = os.getenv("TOKEN")
CHANNEL_ID = "@S1ecurity_Pro"
CHANNEL_LINK = "https://t.me/S1ecurity_Pro"
BOT_NAME = "آمن PRO"

CHECK_MODE = {}

# ----------------- دوال المساعدة -----------------
async def is_member(user_id, context):
    try:
        member = await context.bot.get_chat_member(chat_id=CHANNEL_ID, user_id=user_id)
        return member.status in ["member", "administrator", "creator", "owner"]
    except (BadRequest, Forbidden):
        return False

def get_kb(type="main"):
    if type == "main":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("🏛️ من نحن", callback_data='about')],
            [InlineKeyboardButton("🎯 الرؤية", callback_data='goals')],
            [InlineKeyboardButton("🎓 دورات أمنPRO", callback_data='courses_menu')],
            [InlineKeyboardButton("🔍 فحص الروابط", callback_data='check')],
            [InlineKeyboardButton("📜 الشهادات", callback_data='cert')],
            [InlineKeyboardButton("🆘 الدعم الفني", callback_data='help')]   # الاسم المعدل
        ])
    if type == "back":
        return InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ العودة للرئيسية", callback_data='menu')]])
    if type == "sub":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("📢 الاشتراك", url=CHANNEL_LINK)],
            [InlineKeyboardButton("✅ تحقق", callback_data='check_sub')]
        ])
    if type == "courses":
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("1️⃣ مستوى أول- مبتدئ", callback_data='course_1')],
            [InlineKeyboardButton("2️⃣ مستوى ثاني- متوسط", callback_data='course_2')],
            [InlineKeyboardButton("3️⃣ مستوى ثالث - محترف", callback_data='course_3')],
            [InlineKeyboardButton("4️⃣ مستوى رابع- PRO", callback_data='course_4')],
            [InlineKeyboardButton("⬅️ رجوع", callback_data='menu')]
        ])

def analyze_link(url):
    url_lower = url.lower()
    threats = []
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    if not url_lower.startswith("https://"):
        threats.append("البروتوكول غير مشفر HTTP")
    if "chatid=" in url_lower:
        threats.append("يحتوي على `chatid`")
    if "c.html" in url_lower:
        threats.append("صفحة مزورة `c.html`")
    if "verify=" in url_lower:
        threats.append("يحتوي `verify`")
    if domain == "faceboook.com":
        threats.append("انتحال فيسبوك")

    intro = "🔍 **فحص الرابط**\nيقوم نظام آمن PRO بتحليل الرابط باستخدام عدة طبقات من الفحص للكشف عن المؤشرات الأمنية، بهدف مساعدتك في تقييم الرابط قبل فتحه."

    if threats:
        result = "❌ **غير آمن**"
        description = "تم رصد مؤشرات تدل على أن الرابط قد يكون ضارًا أو يستخدم في التصيد الاحتيالي أو سرقة البيانات.\nننصح بعدم فتح الرابط أو إدخال أي معلومات شخصية داخله حفاظًا على أمنك الرقمي."
    else:
        result = "✅ **آمن**"
        description = "لم يتم رصد أي مؤشرات خطورة معروفة أثناء الفحص.\nملاحظة: يبقى الالتزام بالحذر وعدم مشاركة بياناتك الشخصية أو كلمات المرور في أي موقع غير موثوق."

    footer = "نعمل دائمًا من أجل تعزيز أمنكم الرقمي وتوفير بيئة أكثر أمانًا للجميع.\n\nآمن PRO\nمعًا نحو فضاء رقمي أكثر أمانًا."

    return f"{intro}\n─────────────────────\nنتيجة التحليل: {result}\n{description}\n\n{footer}"

# ----------------- معالجات الأوامر -----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if await is_member(user_id, context):
        await update.message.reply_text(
            "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
            reply_markup=get_kb("main"),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "⚠️ **يجب عليك الاشتراك أولا في القناة للاستفادة من خدمات البوت**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )

async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data

    # منع الوصول إذا غادر القناة (ما عدا زر التحقق)
    if data != 'check_sub' and not await is_member(user_id, context):
        await query.edit_message_text(
            "⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )
        return

    # ----------------- التحقق من الاشتراك -----------------
    if data == 'check_sub':
        if await is_member(user_id, context):
            await query.edit_message_text(
                "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
                reply_markup=get_kb("main"),
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await query.edit_message_text(
                "❌ **لم يتم العثور على اشتراك.**\nيرجى الاشتراك ثم الضغط على تحقق.",
                reply_markup=get_kb("sub"),
                parse_mode=ParseMode.MARKDOWN
            )
        return

    # ----------------- القائمة الرئيسية -----------------
    if data == 'menu':
        await query.edit_message_text(
            "🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.",
            reply_markup=get_kb("main"),
            parse_mode=ParseMode.MARKDOWN
        )

    # ----------------- من نحن -----------------
    elif data == 'about':
        await query.edit_message_text(
            "🏛️ **من نحن**\n\n"
            "آمن PRO فريق متخصص في الأمن السيبراني، يضم خبرات في البرمجة، وتحليل التهديدات الرقمية، "
            "وتصميم الأنظمة، والتوعية الأمنية.\n\n"
            "نعمل على نشر ثقافة الأمن السيبراني، وتطوير أدوات تساعد المستخدمين على استخدام الإنترنت بأمان، "
            "مع تقديم دورات تدريبية ومحتوى احترافي يواكب أحدث التهديدات الإلكترونية.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )

    # ----------------- الرؤية -----------------
    elif data == 'goals':
        await query.edit_message_text(
            "🎯 **هدف آمن PRO**\n\n"
            "نسعى إلى رفع مستوى الوعي الرقمي، وحماية المستخدمين من الاحتيال والاختراقات والهجمات الإلكترونية، "
            "عبر التدريب، والتوعية، وتوفير أدوات تحقق تساعد على اتخاذ القرار الصحيح قبل التفاعل مع أي رابط أو تطبيق.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )

    # ----------------- قائمة الدورات -----------------
    elif data == 'courses_menu':
        await query.edit_message_text(
            "📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )

    # ----------------- تفاصيل المستويات -----------------
    elif data == 'course_1':
        await query.edit_message_text(
            "**1️⃣ المستوى الأول – المبتدئ**\n\n"
            "يُعد هذا المستوى نقطة البداية لكل من يرغب في تعلم الأمن السيبراني، ويتضمن:\n"
            "• أساسيات الأمن السيبراني.\n"
            "• حماية الهاتف من الاختراق والتجسس.\n"
            "• التعامل الآمن مع التطبيقات والروابط.\n"
            "• رفع مستوى الوعي الرقمي وكيفية اكتشاف محاولات الاحتيال والهندسة الاجتماعية.",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_2':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_3':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'course_4':
        await query.edit_message_text(
            "للاشتراك انتظر الإعلان على قنواتنا الرسمية",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )

    # ----------------- الشهادات والدعم -----------------
    elif data == 'cert':
        await query.edit_message_text(
            "نعمل على التطوير من أجل تصديق الشهادات وفق قاعدة بيانات رسمية",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
    elif data == 'help':
        # تم إصلاح الخطأ باستخدام parse_mode=None حتى لا يتعارض الرابط مع تنسيق Markdown
        await query.edit_message_text(
            "اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0",
            reply_markup=get_kb("back")
            # بدون parse_mode (None) تظهر الرسالة نصاً عادياً والرابط يبقى قابلاً للنقر
        )

    # ----------------- فحص الروابط -----------------
    elif data == 'check':
        CHECK_MODE[user_id] = True
        await query.edit_message_text(
            "🔍 **فحص الروابط**\n\n"
            "أرسل الرابط الذي تريد فحصه، وسيقوم النظام بتحليله وإعلامك بالنتيجة.\n\n"
            "ملاحظة: يفضل إرسال الرابط كرسالة منفصلة.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )

async def messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text

    # التحقق من الاشتراك
    if not await is_member(user_id, context):
        await update.message.reply_text(
            "⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**",
            reply_markup=get_kb("sub"),
            parse_mode=ParseMode.MARKDOWN
        )
        return

    # ------- فحص الروابط -------
    if CHECK_MODE.get(user_id, False):
        if "http" in text:
            urls = re.findall(r'(https?://[^\s]+)', text)
            url_to_check = urls[0] if urls else text

            msg = await update.message.reply_text("⏳ جاري الفحص...")
            result = analyze_link(url_to_check)
            try:
                await msg.delete()
            except:
                pass
            await update.message.reply_text(
                result,
                disable_web_page_preview=True,
                reply_markup=get_kb("back"),
                parse_mode=ParseMode.MARKDOWN
            )
            CHECK_MODE.pop(user_id, None)  # إنهاء وضع الفحص
        else:
            await update.message.reply_text(
                "⚠️ الرجاء إرسال رابط صحيح يبدأ بـ http:// أو https://",
                reply_markup=get_kb("back")
            )
        return

    # ------- معالجة الأزرار النصية (الكيبورد المخصص) -------
    if text == "🏛️ من نحن":
        await update.message.reply_text(
            "🏛️ **من نحن**\n\n"
            "آمن PRO فريق متخصص في الأمن السيبراني، يضم خبرات في البرمجة، وتحليل التهديدات الرقمية، "
            "وتصميم الأنظمة، والتوعية الأمنية.\n\n"
            "نعمل على نشر ثقافة الأمن السيبراني، وتطوير أدوات تساعد المستخدمين على استخدام الإنترنت بأمان، "
            "مع تقديم دورات تدريبية ومحتوى احترافي يواكب أحدث التهديدات الإلكترونية.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🎯 الرؤية":
        await update.message.reply_text(
            "🎯 **هدف آمن PRO**\n\n"
            "نسعى إلى رفع مستوى الوعي الرقمي، وحماية المستخدمين من الاحتيال والاختراقات والهجمات الإلكترونية، "
            "عبر التدريب، والتوعية، وتوفير أدوات تحقق تساعد على اتخاذ القرار الصحيح قبل التفاعل مع أي رابط أو تطبيق.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🎓 دورات أمنPRO":
        await update.message.reply_text(
            "📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:",
            reply_markup=get_kb("courses"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🔍 فحص الروابط":
        CHECK_MODE[user_id] = True
        await update.message.reply_text(
            "🔍 **فحص الروابط**\n\n"
            "أرسل الرابط الذي تريد فحصه، وسيقوم النظام بتحليله وإعلامك بالنتيجة.\n\n"
            "ملاحظة: يفضل إرسال الرابط كرسالة منفصلة.",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "📜 الشهادات":
        await update.message.reply_text(
            "نعمل على التطوير من أجل تصديق الشهادات وفق قاعدة بيانات رسمية",
            reply_markup=get_kb("back"),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    if text == "🆘 الدعم الفني":
        # تم الإصلاح هنا أيضاً
        await update.message.reply_text(
            "اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0",
            reply_markup=get_kb("back")
        )
        return

    # أي رسالة أخرى
    await update.message.reply_text(
        "⚠️ الرجاء استخدام الأزرار للتنقل.",
        reply_markup=get_kb("main"),
        parse_mode=ParseMode.MARKDOWN
    )

# ----------------- تشغيل البوت -----------------
app = Application.builder().token(TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CallbackQueryHandler(buttons))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, messages))
app.run_polling(drop_pending_updates=True)