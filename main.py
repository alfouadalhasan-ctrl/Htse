import os
import re
import hashlib
import zipfile
import io
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
FILE_CHECK_MODE = {}

DANGEROUS_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.dll', '.msi', '.com', '.pif']

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
            [InlineKeyboardButton("🔍 فحص الروابط", callback_data='check'), InlineKeyboardButton("📁 فحص الملفات", callback_data='check_file')],
            [InlineKeyboardButton("📜 الشهادات", callback_data='cert')],
            [InlineKeyboardButton("🆘 الدعم الفني", callback_data='help')]
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
    if not url_lower.startswith("https://"): threats.append("البروتوكول غير مشفر HTTP")
    if "chatid=" in url_lower: threats.append("يحتوي على `chatid`")
    if "c.html" in url_lower: threats.append("صفحة مزورة `c.html`")
    if "verify=" in url_lower: threats.append("يحتوي `verify`")
    if domain == "faceboook.com": threats.append("انتحال فيسبوك")
    intro = "🔍 **فحص الرابط**\nيقوم نظام آمن PRO بتحليل الرابط باستخدام عدة طبقات من الفحص للكشف عن المؤشرات الأمنية، بهدف مساعدتك في تقييم الرابط قبل فتحه."
    if threats:
        result = "❌ **غير آمن**"
        description = f"تم رصد مؤشرات: {', '.join(threats)}\nننصح بعدم فتح الرابط أو إدخال أي معلومات شخصية داخله حفاظًا على أمنك الرقمي."
    else:
        result = "✅ **آمن**"
        description = "لم يتم رصد أي مؤشرات خطورة معروفة أثناء الفحص.\nملاحظة: يبقى الالتزام بالحذر وعدم مشاركة بياناتك الشخصية أو كلمات المرور في أي موقع غير موثوق."
    footer = "نعمل دائمًا من أجل تعزيز أمنكم الرقمي وتوفير بيئة أكثر أمانًا للجميع.\n\nآمن PRO\nمعًا نحو فضاء رقمي أكثر أمانًا."
    return f"{intro}\n─────────────────────\nنتيجة التحليل: {result}\n{description}\n\n{footer}"

def analyze_file(file_bytes: bytes, file_name: str):
    threats = []
    warnings = []
    size = len(file_bytes)
    ext = os.path.splitext(file_name)[1].lower()
    header = file_bytes[:4]
    md5 = hashlib.md5(file_bytes).hexdigest()
    if ext in DANGEROUS_EXTS: threats.append(f"امتداد تنفيذي خطر `{ext}`")
    if re.search(r'\.(jpg|png|pdf|docx)\.(exe|bat|js|scr)$', file_name, re.I): threats.append(f"خدعة الامتداد المزدوج `{file_name}`")
    real = "غير معروف"
    if header.startswith(b'MZ'): real = "EXE تنفيذي Windows"
    elif header.startswith(b'\x7fELF'): real = "ELF تنفيذي Linux"
    elif header.startswith(b'PK\x03\x04'): real = "ZIP/APK/JAR"
    if ext in ['.jpg','.png','.pdf'] and real.startswith("EXE"): threats.append(f"تنكر خطير: يدعي أنه {ext} لكنه في الحقيقة {real}")
    if ext == '.zip' or header.startswith(b'PK\x03\x04'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                for inner in z.namelist():
                    if os.path.splitext(inner)[1].lower() in DANGEROUS_EXTS:
                        threats.append(f"داخل المضغوط يوجد ملف خطر: `{inner}`")
        except: warnings.append("ملف مضغوط تالف أو محمي بكلمة سر")
    try:
        txt = file_bytes[:4000].decode('utf-8', errors='ignore').lower()
        if 'powershell' in txt and 'bypass' in txt: threats.append("أوامر PowerShell Bypass مشبوهة")
        if 'eval(' in txt and 'base64' in txt: threats.append("كود مشوش eval+base64")
    except: pass
    if threats: status = "❌ **ملف خطير - لا تفتحه**"; details = "\n".join([f"• {t}" for t in threats])
    elif warnings: status = "⚠️ **ملف مشبوه**"; details = "\n".join([f"• {w}" for w in warnings])
    else: status = "✅ **الملف نظيف ظاهرياً**"; details = "لم نرصد مؤشرات خطورة في بنية الملف."
    report = f"📁 **فحص الملفات - آمن PRO**\n─────────────────────\n📄 الاسم: `{file_name}`\n📦 الحجم: {size/1024:.1f} KB\n🔍 التوقيع الحقيقي: {real}\n🧬 MD5: `{md5[:16]}...`\n─────────────────────\n{status}\n{details}\n─────────────────────\nآمن PRO"
    return report

# ----------------- معالجات الأوامر -----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if await is_member(user_id, context):
        await update.message.reply_text("🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.", reply_markup=get_kb("main"), parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text("⚠️ **يجب عليك الاشتراك أولا في القناة للاستفادة من خدمات البوت**", reply_markup=get_kb("sub"), parse_mode=ParseMode.MARKDOWN)

async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data
    if data!= 'check_sub' and not await is_member(user_id, context):
        await query.edit_message_text("⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**", reply_markup=get_kb("sub"), parse_mode=ParseMode.MARKDOWN)
        return
    if data == 'check_sub':
        if await is_member(user_id, context):
            await query.edit_message_text("🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.", reply_markup=get_kb("main"), parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("❌ **لم يتم العثور على اشتراك.**\nيرجى الاشتراك ثم الضغط على تحقق.", reply_markup=get_kb("sub"), parse_mode=ParseMode.MARKDOWN)
        return
    if data == 'menu':
        CHECK_MODE.pop(user_id, None); FILE_CHECK_MODE.pop(user_id, None)
        await query.edit_message_text("🛡️ **أهلاً بك في بوت أمن PRO**\nاختر الخدمة التي تريدها من الأزرار أدناه.", reply_markup=get_kb("main"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'about':
        await query.edit_message_text("🏛️ **من نحن**\n\nآمن PRO فريق متخصص في الأمن السيبراني، يضم خبرات في البرمجة، وتحليل التهديدات الرقمية، وتصميم الأنظمة، والتوعية الأمنية.\n\nنعمل على نشر ثقافة الأمن السيبراني، وتطوير أدوات تساعد المستخدمين على استخدام الإنترنت بأمان، مع تقديم دورات تدريبية ومحتوى احترافي يواكب أحدث التهديدات الإلكترونية.", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'goals':
        await query.edit_message_text("🎯 **هدف آمن PRO**\n\nنسعى إلى رفع مستوى الوعي الرقمي، وحماية المستخدمين من الاحتيال والاختراقات والهجمات الإلكترونية، عبر التدريب، والتوعية، وتوفير أدوات تحقق تساعد على اتخاذ القرار الصحيح قبل التفاعل مع أي رابط أو تطبيق.", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'courses_menu':
        await query.edit_message_text("📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:", reply_markup=get_kb("courses"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'course_1':
        await query.edit_message_text("**1️⃣ المستوى الأول – المبتدئ**\n\nيُعد هذا المستوى نقطة البداية لكل من يرغب في تعلم الأمن السيبراني، ويتضمن:\n• أساسيات الأمن السيبراني.\n• حماية الهاتف من الاختراق والتجسس.\n• التعامل الآمن مع التطبيقات والروابط.\n• رفع مستوى الوعي الرقمي وكيفية اكتشاف محاولات الاحتيال والهندسة الاجتماعية.", reply_markup=get_kb("courses"), parse_mode=ParseMode.MARKDOWN)
    elif data in ['course_2','course_3','course_4']:
        await query.edit_message_text("للاشتراك انتظر الإعلان على قنواتنا الرسمية", reply_markup=get_kb("courses"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'cert':
        await query.edit_message_text("نعمل على التطوير من أجل تصديق الشهادات وفق قاعدة بيانات رسمية", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'help':
        await query.edit_message_text("اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0", reply_markup=get_kb("back"))
    elif data == 'check':
        CHECK_MODE[user_id] = True; FILE_CHECK_MODE.pop(user_id, None)
        await query.edit_message_text("🔍 **فحص الروابط**\n\nأرسل الرابط الذي تريد فحصه، وسيقوم النظام بتحليله وإعلامك بالنتيجة.\n\nملاحظة: يفضل إرسال الرابط كرسالة منفصلة.", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
    elif data == 'check_file':
        FILE_CHECK_MODE[user_id] = True; CHECK_MODE.pop(user_id, None)
        await query.edit_message_text("📁 **فحص الملفات المتقدم**\n\nأرسل الملف الآن (APK, PDF, ZIP, EXE, Word...)\nالحد الأقصى 20MB", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)

async def messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    if not await is_member(user_id, context):
        await update.message.reply_text("⚠️ **يجب عليك الاشتراك أولاً للاستفادة من الخدمات.**", reply_markup=get_kb("sub"), parse_mode=ParseMode.MARKDOWN)
        return
    # ------- فحص الروابط (موجود كما هو) -------
    if CHECK_MODE.get(user_id, False):
        if "http" in text:
            urls = re.findall(r'(https?://[^\s]+)', text)
            url_to_check = urls[0] if urls else text
            msg = await update.message.reply_text("⏳ جاري الفحص...")
            result = analyze_link(url_to_check)
            try: await msg.delete()
            except: pass
            await update.message.reply_text(result, disable_web_page_preview=True, reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
            CHECK_MODE.pop(user_id, None)
        else:
            await update.message.reply_text("⚠️ الرجاء إرسال رابط صحيح يبدأ بـ http:// أو https://", reply_markup=get_kb("back"))
        return
    # باقي الأزرار النصية
    if text == "🏛️ من نحن":
        await update.message.reply_text("🏛️ **من نحن**\n\nآمن PRO فريق متخصص...", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "🎯 الرؤية":
        await update.message.reply_text("🎯 **هدف آمن PRO**\n\nنسعى إلى رفع مستوى الوعي...", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "🎓 دورات أمنPRO":
        await update.message.reply_text("📚 **دورات آمن PRO**\nاختر المستوى المناسب لك:", reply_markup=get_kb("courses"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "🔍 فحص الروابط":
        CHECK_MODE[user_id] = True
        await update.message.reply_text("🔍 **فحص الروابط**\n\nأرسل الرابط الذي تريد فحصه...", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "📁 فحص الملفات":
        FILE_CHECK_MODE[user_id] = True
        await update.message.reply_text("📁 **فحص الملفات**\n\nأرسل الملف الآن...", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "📜 الشهادات":
        await update.message.reply_text("نعمل على التطوير من أجل تصديق الشهادات وفق قاعدة بيانات رسمية", reply_markup=get_kb("back"), parse_mode=ParseMode.MARKDOWN)
        return
    if text == "🆘 الدعم الفني":
        await update.message.reply_text("اطرح سؤالك هنا\nhttps://t.me/+wdWPPmwpg_w5NmU0", reply_markup=get_kb("back"))
        return
    await update.message.reply_text("⚠️ الرجاء استخدام الأزرار للتنقل.", reply_markup=get_kb("main"), parse_mode=ParseMode.MARKDOWN)

async def handle_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await is_member(user_id, context):
        await update.message.reply_text("⚠️ **يجب عليك الاشتراك أولاً**", reply_markup=get_kb("sub"), parse_mode=ParseMode.MARKDOWN)
        return
    doc = update.message.document or (update.message.photo[-1] if update.message.photo else None)
    if not doc: return
    file_name = getattr(doc, 'file_name', f"photo_{doc.file_id}.jpg")
    file_size = getattr(doc, 'file_size', 0)
    if file_size > 20 * 1024 * 1024:
        await update.message.reply_text("❌ الملف أكبر من 20MB", reply_markup=get_kb("back"))
        return
    status_msg = await update.message.reply_text(f"⏳ جاري تحليل الملف `{file_name}`...", parse_mode=ParseMode.MARKDOWN)
    try:
        tg_file = await update.message.document.get_file() if update.message.document else await update.message.photo[-1].get_file()
        file_bytes = bytes(await tg_file.download_as_bytearray())
        report = analyze_file(file_bytes, file_name)
        try: await status_msg.delete()
        except: pass
        await update.message.reply_text(report, parse_mode=ParseMode.MARKDOWN, reply_markup=get_kb("back"), disable_web_page_preview=True)
        FILE_CHECK_MODE.pop(user_id, None)
    except Exception as e:
        try: await status_msg.delete()
        except: pass
        await update.message.reply_text(f"❌ خطأ أثناء الفحص: {e}", reply_markup=get_kb("back"))

# ----------------- تشغيل البوت -----------------
app = Application.builder().token(TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CallbackQueryHandler(buttons))
app.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO, handle_files))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, messages))
app.run_polling(drop_pending_updates=True)
