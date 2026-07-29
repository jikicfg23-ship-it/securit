// =========================================================================
// 🔓 مصفوفة كلمات السر المصرح لها بالدخول إلى الأداة لحماية الخصوصية
// يمكنك إضافة أي كلمات سر جديدة هنا إلى ما لا نهاية وبأي عدد خانات تحبه
// فقط ضع فاصلة (,) ثم اكتب الكلمة الجديدة داخل علامات الاقتباس كالتالي: "your_password"
// =========================================================================
const ALLOWED_PASSWORDS = ["13", "14"];


// عناصر التحكم في شاشات الدخول والتحقق
const lockScreen = document.getElementById('lock-screen');
const analyzerScreen = document.getElementById('analyzer-screen');
const btnLogin = document.getElementById('btn-login');
const appPasswordInput = document.getElementById('app-password');
const loginError = document.getElementById('login-error');

btnLogin.addEventListener('click', checkAccessPassword);
appPasswordInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') checkAccessPassword(); });

function checkAccessPassword() {
    const enteredPass = appPasswordInput.value.trim();
    if (ALLOWED_PASSWORDS.includes(enteredPass)) {
        loginError.innerText = "";
        appPasswordInput.value = ""; 
        lockScreen.classList.remove('active');
        analyzerScreen.classList.add('active');
    } else {
        loginError.innerText = "❌ رمز المرور خاطئ! غير مصرح لك بفتح الأداة.";
    }
}

document.getElementById('btn-lock-out').addEventListener('click', () => {
    document.getElementById('result-board').style.display = 'none';
    document.getElementById('url-input').value = "";
    analyzerScreen.classList.remove('active');
    lockScreen.classList.add('active');
});


// ================= 🚀 محرك الفحص والتحليل السيبراني الفائق والأحدث =================
const urlInput = document.getElementById('url-input');
const btnAnalyze = document.getElementById('btn-analyze');
const resultBoard = document.getElementById('result-board');

btnAnalyze.addEventListener('click', runUrlAnalysis);

function runUrlAnalysis() {
    let rawUrl = urlInput.value.trim();
    if (!rawUrl) {
        alert("برجاء إدخال رابط أولاً لبدء الفحص والمحاكاة!");
        return;
    }

    // تجهيز وتنظيف الرابط لكي يفهمه مفسر المتصفح بدقة
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
        rawUrl = 'https://' + rawUrl;
    }

    try {
        const urlObj = new URL(rawUrl);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        
        let threatScore = 0; // نظام احتساب نقاط خطورة الرابط التراكمي
        let domainAnalysisLog = "";
        let punycodeLog = "✅ لم يتم العثور على محاولات خداع بصري؛ الحروف متناسقة مع معايير الأنظمة الدولية.";
        let trackerLog = "🧹 الرابط نظيف تماماً من أجهزة التتبع ومعاملات الطرف الثالث المزعجة.";

        // ---------------- [1. مطهر ومعقم ومعالجة التتبع الفورية] ----------------
        // قائمة سوداء موسعة لأحدث معاملات التتبع والتحليلات السيبرانية لعام 2026
        const trackerParams = [
            'fbclid', 'gclid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'yclid', 'twclid', 'msclkid', 'mc_eid', 'rb_clickid', 's_kwcid', 'igshid', 'ttclid'
        ];
        
        let cleanedSearchParams = new URLSearchParams();
        let trackersFound = [];
        
        urlObj.searchParams.forEach((value, key) => {
            if (trackerParams.includes(key.toLowerCase()) || key.toLowerCase().startsWith('utm_')) {
                trackersFound.push(key);
            } else {
                cleanedSearchParams.append(key, value);
            }
        });

        // إعادة تجميع الرابط النظيف بعد التطهير الكامل
        const cleanSearchString = cleanedSearchParams.toString();
        const cleanUrl = urlObj.origin + urlObj.pathname + (cleanSearchString ? '?' + cleanSearchString : '');

        if (trackersFound.length > 0) {
            threatScore += 1;
            trackerLog = `⚙️ تم كشف وتطهير (${trackersFound.length}) من برمجيات التتبع الخلفي المخفية ومنها: [${trackersFound.join(', ')}].`;
        }

        // ---------------- [2. فحص النطاقات الخبيثة المتقدمة وعميقة التفرع] ----------------
        // قائمة سوداء محدثة لأخطر امتدادات النطاقات الإقليمية والمشبوهة رخيصة الثمن
        const blacklistedExtensions = ['.ru', '.cn', '.xyz', '.tk', '.gq', '.cf', '.ml', '.ga', '.top', '.club', '.work', '.live', '.info', '.cc', '.su', '.click'];
        // كلمات دلالية هندسية واجتماعية تلتصق دائماً بروابط تصيد البنوك والجوائز المزيفة
        const phishingKeywords = ['free-', 'login', 'secure', 'verify', 'update', 'banking', 'netflix', 'crypto', 'gift', 'bonus', 'wallet', 'signin', 'account', 'claim', 'support'];

        let matchExt = blacklistedExtensions.find(ext => hostname.endsWith(ext));
        let matchWord = phishingKeywords.filter(keyword => hostname.includes(keyword));

        if (matchExt) {
            threatScore += 3;
            domainAnalysisLog += `❌ امتداد النطاق المريب (${matchExt}) مصنف عالي الخطورة ومحجوب في بعض جدران الحماية السيبرانية الوطنية. `;
        }
        if (matchWord.length > 0) {
            threatScore += 2;
            domainAnalysisLog += `⚠️ النطاق يحتوي على كلمات هندسة اجتماعية مشبوهة لصيد البيانات مثل: [${matchWord.join(', ')}]. `;
        }

        // ---------------- [3. كشف النطاقات الفرعية العميقة الملتوية (Subdomain Flood)] ----------------
        // الحيلة الخبيثة الشهيرة: كتابة (://facebook.com.secure-login-portal.ru) لخداع الضحية
        const domainParts = hostname.split('.');
        if (domainParts.length > 4) { // إذا كان النطاق يحتوي على أكثر من 4 تفريعات فرعية
            threatScore += 2;
            domainAnalysisLog += `🚨 تحذير: هيكلة النطاق فرعية وعميقة جداً (${domainParts.length} أجزاء)، وهي استراتيجية تضليلية لعزل وتغطية اسم الموقع الحقيقي الحاضن للملفات وضمان إفلاته من الحجب. `;
        }

        if (!domainAnalysisLog) {
            domainAnalysisLog = `✅ اسم النطاق الرئيسي هو (${hostname})؛ يظهر ببنية سليمة وغير مدرج بالقوائم الاستكشافية المحلية الفورية.`;
        }

        // ---------------- [4. كشف الاحتيال البصري المتقدم (Homograph Attacks / Punycode)] ----------------
        // حيلة الهاكرز المتقدمة: استخدام حرف روسي أو يوناني يشبه تماماً الحرف الإنجليزي (مثل استخدام а الروسية بدلاً من a الإنجليزية في كلمة google)
        // المواقع السليمة لا تخلط حروف اللغات المختلفة في النطاق الصافي
        const nonAsciiRegex = /[^\x00-\x7F]/;
        if (nonAsciiRegex.test(hostname)) {
            threatScore += 4; // تهديد عالي جداً
            punycodeLog = `🛑 كشف اختراق الهوية البصرية (Homograph Attack)! النطاق يستخدم حروفاً دولية ملتوية وخفية تشبه الأسماء العالمية الشهيرة لخداع عين المستخدم وتجاوز الحظر الذكي للمتصفح.`;
        }

        // ---------------- [5. فحص امتدادات الملفات التنفيذية المخفية والملغمة] ----------------
        // كشف محاولات تنزيل ملفات التجسس والفدية التلقائية بمجرد فتح الرابط (Drive-by Download)
        const dangerousPayloads = ['.exe', '.scr', '.bat', '.vbs', '.msi', '.pif', '.cmd', '.jar', '.apk', '.zip', '.rar'];
        let matchPayload = dangerousPayloads.find(payloadExt => pathname.endsWith(payloadExt));
        if (matchPayload) {
            threatScore += 4;
            domainAnalysisLog += `\n💥 خطورة قاطعة: الرابط ينتهي مباشرة بملف تشغيلي/مضغوط مغلق ومجهول من النوع (${matchPayload})، مما قد يؤدي لتنزيل فيروس فدية أو برمجية خبيثة فور فتحه بالمتصفح!`;
        }

        // ---------------- [6. فحص الروابط المختصرة الملتوية وتتبع مساراتها] ----------------
        const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'rb.gy', 'is.gd', 'buff.ly', 'adf.ly'];
        if (shorteners.includes(hostname)) {
            if (threatScore < 2) threatScore = 2; // رفع مستوى التحذير لبرتقالي كحد أدنى
            punycodeLog = `🔗 هذا الرابط مقنع خلف خدمة اختصار روابط شهيرة (${hostname}). تم تصميمها لإخفاء المسار النهائي الفعلي للموقع الحاضن، ننصح بنسخ الرابط المطهّر في الحافظة وتتبعه بحذر.`;
        }


        // ================= 📊 صياغة القرار الأمني النهائي للمحرك =================
        const statusBadge = document.getElementById('res-status');
        const cleanUrlEl = document.getElementById('res-clean-url');
        const domainInfoEl = document.getElementById('res-domain-info');
        const punycodeInfoEl = document.getElementById('res-punycode-info');
        const trackerInfoEl = document.getElementById('res-tracker-info');

        // تصنيف الدرجات بناءً على نقاط التهديد التراكمية الناتجة من آليات الفحص
        if (threatScore >= 4) {
            statusBadge.className = "badge danger";
            statusBadge.innerText = "🛑 عالي الخطورة / خبيث مؤكد";
        } else if (threatScore >= 2) {
            statusBadge.className = "badge warning";
            statusBadge.innerText = "⚠️ مشبوه / يتطلب حذر شديد";
        } else {
            statusBadge.className = "badge safe";
            statusBadge.innerText = "✅ آمن ونظيف محلياً";
        }

        // تعبئة البيانات المكتشفة بالتقرير لوجهة واجهة المستخدم
        cleanUrlEl.innerText = cleanUrl;
        domainInfoEl.innerText = domainAnalysisLog;
        punycodeInfoEl.innerText = punycodeLog;
        trackerInfoEl.innerText = trackerLog;

        resultBoard.style.display = 'flex';

    } catch (e) {
        alert("تنبيه أمني: صيغة الرابط المدخلة غير مدعومة أو تحتوي على رموز مكسورة؛ يرجى التأكد من كتابة الرابط بشكل كامل وصحيح.");
    }
}

// ميزة نسخ الرابط المطهّر الخالي من ملفات وجواسيس التتبع
document.getElementById('btn-copy-url').addEventListener('click', () => {
    const cleanUrlText = document.getElementById('res-clean-url').innerText;
    if (cleanUrlText && cleanUrlText !== "--") {
        navigator.clipboard.writeText(cleanUrlText);
        alert("تم نسخ الرابط النظيف بعد نزع أجهزة التتبع بنجاح! يمكنك تصفحه الآن بأمان.");
    }
});

