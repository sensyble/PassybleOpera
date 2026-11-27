// Form detection: pure DOM functions (no extension APIs), so tests run them under jsdom.

import { looksLike2faPage } from '../shared/otp-logic.js';

export const FieldKind = Object.freeze({
  USERNAME: 'username',
  CURRENT_PASSWORD: 'current-password',
  NEW_PASSWORD: 'new-password',
  OTP: 'otp',
});

const FILLABLE_TYPES = new Set(['', 'text', 'email', 'tel', 'number', 'password']);

const OTP_STRONG_RE = new RegExp([
  'one ?time', '\\botp\\b', '\\btotp\\b', '\\bhotp\\b', '\\b2 ?fa\\b', '\\bmfa\\b', 'two ?factor',
  '2 ?step', 'second ?factor', 'multi ?factor', 'authenticator', 'authentication code',
  'verification ?code', 'verify ?code', 'security ?code', 'auth ?code', 'sms ?code', 'login ?code',
  'sign ?in ?code', 'confirmation ?code', 'passcode', '\\btwo ?fa\\b', '\\btfa\\b', '\\botc\\b',
  '\\b(mfa|otp|totp|hotp|2fa|tfa|sms)(code|token|pin)\\b',
  'bestätigungscode', 'sicherheitscode', 'einmal', 'verifizierungscode', 'anmeldecode',
  'code de vérification', 'code de sécurité', 'code de confirmation', 'usage unique', 'à deux facteurs',
  'código de verificación', 'código de seguridad', 'código de verificação', 'verificación', 'verificação',
  'codice di verifica', 'codice di sicurezza', 'verificatiecode', 'beveiligingscode',
  'kod weryfikacyjny', 'kod jednorazowy', 'код подтверждения', 'одноразов',
  '確認コード', '認証コード', 'ワンタイム', '验证码', '驗證碼', '动态码', '인증 ?번호', '인증 ?코드',
  'kode verifikasi', 'kode keamanan', 'सत्यापन कोड', 'ओटीपी',
].join('|'), 'i');

// Only counts when the field is code-shaped or the form mentions 2FA.
const OTP_WEAK_RE = /\b(code|codigo|código|codice|kod|kode|код|pin|token|verify|verification|challenge)\b|कोड|コード|코드/i;

// Codes that are never a sign-in code, whatever else the field says.
const OTP_NEGATIVE_RE = new RegExp([
  'zip', 'postal', 'post ?code', '\\bplz\\b', 'pincode', 'promo', 'coupon', 'voucher', 'discount', 'gift',
  'redeem', 'reward', 'loyalty', '\\bbonus', 'referr?al', 'invite', 'invitation', 'captcha', 'country',
  'area ?code', 'dial', 'calling ?code', 'tracking', 'sort ?code', 'swift', 'iban', '\\bbic\\b', 'cvv', 'cvc',
  'csc', 'card', 'search', 'query', 'product', 'serial', 'license', 'licence', 'activation key',
  'postleitzahl', 'gutschein', 'rabat', 'aktionscode', 'einladung',
  'code postal', 'réduction', 'parrainage', 'cadeau',
  'código postal', 'cupón', 'cupom', 'descuento', 'desconto', 'regalo', 'invitación', 'convite',
  'sconto', 'buono', 'codice postale', 'korting', 'cadeaubon', 'kupon', 'zniżk',
  'промокод', 'купон', 'скидк', 'подарочн', 'индекс', 'капч',
  'クーポン', 'プロモ', '割引', 'ギフト', '招待', '郵便番号', '画像認証',
  '优惠', '優惠', '折扣', '礼品', '禮品', '礼物', '禮物', '邀请', '邀請', '邮编', '邮政编码', '郵遞區號',
  '兑换', '兌換', '图形验证码', '圖形驗證碼', '图片验证码', '圖片驗證碼',
  '쿠폰', '할인', '프로모션', '선물', '초대', '우편번호', '자동입력 ?방지',
  'कूपन', 'छूट', 'प्रोमो', 'उपहार', 'आमंत्रण', 'पिन ?कोड',
  'diskon', 'potongan', 'hadiah', 'undangan', 'kode pos',
].join('|'), 'i');

// Ordinary text fields that hold no code. Unlike OTP_NEGATIVE_RE these give way when the field also
// names a code ("Code from the text message").
const CYR = '(?<![а-яё])';
// Name words are kept apart (NAME_WORDS) because "user name" is a username.
const NOT_TEXT_WORDS = [
  '\\bsubject', '\\btitle', '\\bmessage', '\\bmsg\\b', '\\bcomment', '\\brepl(y|ies)\\b', '\\bnotes?\\b',
  '\\bcaption', '\\bdescri', '\\bsummary', '\\bkeywords?\\b', '\\bfilter', '\\bcompose', '\\brecipient',
  '\\bchat\\b', '\\bheadline', '\\bbio\\b', '\\babout\\b', '\\bstatus\\b', '\\bfeedback', '\\breview',
  '\\bquestion', '\\btopic', '\\btags?\\b', '\\baddress', '\\bstreet',
  '\\bcity\\b', '\\blocation', '\\burl\\b', '\\blink\\b', '\\bwebsite', '\\bamount', '\\bprice', '\\bquantity',
  '\\bqty\\b',
  '\\bbetreff', '\\btitel', '\\bsuche', '\\bnachricht', '\\bkommentar', '\\bnotiz', '\\bbeschreibung',
  '\\bbetrag', '\\badresse', '\\bstraße', '\\bstadt\\b',
  '\\bobjet\\b', '\\btitre', '\\brecherch', '\\bcommentaire', '\\brépond', '\\blégende', '\\bmontant',
  '\\bville\\b',
  '\\basunto', '\\btítulo', '\\bbusca', '\\bbúsqueda', '\\bmensaje', '\\bmensagem', '\\bcomentar',
  '\\bcomentário', '\\bresponder', '\\bnota\\b', '\\bdescripción', '\\bdescrição', '\\bimporte',
  '\\bmonto\\b', '\\bdirección', '\\bciudad', '\\bassunto', '\\bpesquis', '\\bendereço',
  '\\bcidade', '\\boggetto', '\\btitolo', '\\bcerca\\b', '\\bmessaggio', '\\bcommento',
  '\\brispondi', '\\bdescrizione', '\\bimporto', '\\bindirizzo', '\\bcittà',
  '\\bonderwerp', '\\bzoek', '\\bbericht', '\\breactie', '\\bbeschrijving', '\\bbedrag',
  '\\btemat\\b', '\\btytuł', '\\bszukaj', '\\bwiadomoś', '\\bkomentarz', '\\bopis\\b', '\\bkwota',
  `${CYR}(тема|заголов|поиск|сообщени|комментари|ответить|описани|сумма|адрес|город|фамили)`,
  '件名', 'タイトル', '検索', 'メッセージ', 'コメント', '返信', '説明', '金額', '住所',
  '主题', '主題', '标题', '標題', '搜索', '搜尋', '消息', '留言', '评论', '評論', '回复', '回覆', '描述',
  '金额', '地址',
  '제목', '검색', '메시지', '댓글', '답장', '설명', '금액', '주소',
  'विषय', 'खोज', 'संदेश', 'टिप्पणी', 'शीर्षक', 'विवरण', 'राशि',
  '\\bsubjek', '\\bjudul', '\\bcari\\b', '\\bpencarian', '\\bpesan\\b', '\\bkomentar', '\\bbalas',
  '\\bdeskripsi', '\\bjumlah', '\\balamat', '\\bkota\\b',
];
const NAME_WORDS = [
  '\\bnames?\\b', '\\bnickname', '\\bnom\\b', '\\bnombre', '\\bnome\\b', '\\bnaam\\b', '\\bnama\\b',
  `${CYR}имя`, '名前', '氏名', '姓名', '名称', '名稱', '이름', 'नाम',
];
const NOT_CODE_RE = new RegExp([...NOT_TEXT_WORDS, ...NAME_WORDS].join('|'), 'i');

function notCodeField(hints) {
  return NOT_CODE_RE.test(hints) && !OTP_STRONG_RE.test(hints) && !OTP_WEAK_RE.test(hints);
}

const USER_RE = new RegExp([
  'user', 'login', 'log ?in', 'sign ?in', 'e ?mail', '\\bmail\\b', 'account', 'identifier',
  '\\buid\\b', '\\bid\\b', 'member', 'customer', 'handle', 'nick',
  'benutzer', 'nutzer', 'anmelde', 'kennung', 'utilisateur', 'identifiant', 'courriel', 'usuario',
  'correo', 'utente', 'gebruiker', 'użytkownik', 'логин', 'почт', 'пользовател', 'ユーザー',
  'メール', '用户', '账号', '帳號', '아이디', '이메일', '\\bbruker', '\\be ?post',
].join('|'), 'i');

// The username rule: a text field is a username only with positive evidence (autocomplete, type=email,
// or username/e-mail/phone words), and negative evidence wins over words. Standing before a password
// is not enough, except in the classic unlabelled login form (anonymousUsername).
const USERNAME_WORDS_RE = new RegExp([
  'user', 'login', 'log ?in', 'log ?on', 'sign ?in', 'email', '\\be ?mail\\b', '\\bmail\\b',
  '\\baccount(?!ing|ant)', 'identifier', '\\buid\\b', '\\bmember', '\\bcustomer', '\\bnick',
  '\\b(client|employee|staff|student) ?(id|no|num|number|code)\\b',
  'benutzer', 'nutzer', 'anmelde', 'kennung', '\\bkonto\\b', 'utilisateur', 'identifiant', 'courriel', '\\bcompte\\b',
  'usuario', 'usuário', 'correo', '\\bcuenta\\b', 'utente', 'gebruiker', 'użytkownik', 'логин', 'почт', 'пользовател',
  '\\bbruker', '\\be ?post',
  'ユーザ', 'メール', 'ログイン', 'アカウント', '用户', '用戶', '使用者', '账号', '帳號', '账户', '帳戶', '邮箱', '郵箱',
  '邮件', '郵件', '登录', '登入', '아이디', '이메일', '사용자', '계정', '로그인',
  'उपयोगकर्ता', 'यूज़र', 'यूजर', 'लॉगिन', 'ईमेल', 'ई मेल', 'खाता', '\\bpengguna\\b', '\\bsurel\\b', '\\bakun\\b',
].join('|'), 'i');

// Weaker than a username or e-mail word.
const PHONE_LOGIN_RE = /phone|mobile|\bcell\b|\bhandy\b|telefon|téléphone|teléfono|\bportable\b|móvil|celular|телефон|電話|电话|手机|手機|携帯|휴대폰|전화|मोबाइल|फ़ोन|फोन|\bponsel\b|\btelepon\b|\bno(mor)? hp\b/i;

// Whole words where a login's id could contain them by accident ("login-page-email", LinkedIn's
// "session_key"), so no bare "page", "post" or "key".
const NOT_USERNAME_RE = new RegExp([
  ...NOT_TEXT_WORDS,
  'search', 'query', 'captcha', 'coupon', 'promo', 'voucher', 'newsletter', 'subscribe', 'given', 'family', 'surname',
  'address', 'street', 'city', 'zip', 'postal', 'company', 'message', 'comment', 'subject', 'title', 'amount',
  'quantity', 'friend', 'recipient', 'gift',
  '\\b(first|last|middle|full|maiden|business|organi[sz]ation|site|blog|post|page|file|product|project|event|group|team|domain|display|shop|store|brand|pet|room|host|your|real|contact|customer|card|bank) ?names?\\b',
  'publish', 'publication', 'schedul', '\\bslug\\b', 'permalink', 'excerpt', 'categor', '\\bdraft\\b', '\\bauthor\\b', '\\bvisibility\\b',
  '\\bdate\\b', '\\bdates\\b', '\\bdatetime', '\\btime\\b', 'timestamp', 'timezone', 'deadline',
  '\\buri\\b', '\\bweb ?site', 'homepage', '\\bdomain(?! ?(user|login|account))', '\\bhost ?name\\b', '\\bhost\\b', '\\bport\\b', '\\bserver\\b', '\\bdatabase\\b',
  '\\bcost\\b', '\\btotal\\b', '\\bsku\\b', '\\bproduct', '\\bproject', '\\border\\b', '\\binvoice', '\\bevent\\b', '\\bfolder\\b', '\\bpath\\b',
  '(?<!(user|login|member|customer|client|employee|account) ?)\\bcode\\b', '\\btoken\\b', '\\bsecret\\b', 'api ?key', 'licen[cs]e', '\\bserial\\b', 'activation',
  '\\bwi ?fi\\b', '\\bssid\\b', '\\bnetwork\\b', '\\broom\\b', '\\bmeeting\\b',
  'veröffentl', 'datum', '\\buhrzeit\\b', '\\bkategorie', '\\bschlagw', '\\bpreis', '\\bmenge\\b', '\\banzahl\\b', '\\bwebseite', '\\bfirma\\b', '\\bvorname', '\\bnachname',
  '\\bpublier', '\\bheure\\b', 'catégorie', 'étiquette', '\\bprix\\b', 'quantité', '\\bsite web', 'prénom', 'société',
  '\\bpublicar', '\\bpublicaci', '\\bfecha', '\\bhora\\b', 'categoría', '\\betiqueta', '\\bprecio', '\\bcantidad', '\\bsitio web', '\\bapellido', '\\bempresa',
  '\\bterbit', '\\bpublikasi', '\\btanggal', '\\bwaktu\\b', '\\bkategori', '\\bharga\\b', '\\bkuantitas', '\\bsitus\\b', '\\btautan', '\\bperusahaan',
  'प्रकाशित', 'प्रकाशन', 'तारीख', 'दिनांक', 'समय', 'श्रेणी', 'टैग', 'कीमत', 'मूल्य', 'मात्रा', 'वेबसाइट', 'पता',
  '公開', '投稿', '日付', '日時', '時間', '時刻', 'カテゴリ', 'タグ', '価格', '数量', 'サイト', 'リンク', '会社',
  '게시', '발행', '공개', '날짜', '시간', '카테고리', '태그', '가격', '수량', '사이트', '링크', '회사',
  '发布', '發布', '公开', '日期', '时间', '分类', '分類', '标签', '標籤', '价格', '價格', '數量', '网站', '網站', '链接', '連結', '公司',
].join('|'), 'i');

// A bare "name" is neither evidence nor contradiction (old login forms use it).
const BARE_NAME_RE = new RegExp(NAME_WORDS.join('|'), 'i');

const NOT_LOGIN_TOKENS = new Set(['name', 'given-name', 'family-name', 'additional-name', 'honorific-prefix',
  'honorific-suffix', 'street-address', 'postal-code', 'country', 'country-name', 'organization',
  'organization-title', 'one-time-code', 'new-password', 'current-password', 'language', 'bday', 'bday-day',
  'bday-month', 'bday-year', 'sex', 'url', 'photo', 'impp', 'transaction-currency', 'transaction-amount',
  'shipping', 'billing']);

function notLoginToken(token) {
  return NOT_LOGIN_TOKENS.has(token) || token.startsWith('cc-') || token.startsWith('address-') ||
    (token.startsWith('tel-') && token !== 'tel-national');
}

// "Email address" and "Company email" name an e-mail, not a postal address or a company.
const EMAIL_WORD_RE = /e ?mail|courriel|correo|почт|メール|邮箱|郵箱|邮件|郵件|이메일|ईमेल|ई मेल|\bsurel\b|\be ?post/i;
const EMAIL_QUALIFIER_RE = /addr(ess)?|adresse|dirección|endereço|indirizzo|alamat|адрес|住所|地址|주소|पता|company|business/gi;

function notUsernameHints(hints) {
  return NOT_USERNAME_RE.test(EMAIL_WORD_RE.test(hints) ? hints.replace(EMAIL_QUALIFIER_RE, ' ') : hints);
}

const USERNAME_NAME_RE = /\b(user ?(name|id)|login|log ?in|sign ?in|identifier|benutzername|identifiant)\b/i;

const NEWSLETTER_RE = /newsletter|subscribe|abonn|updates|offers/i;

const NEW_PASSWORD_RE = new RegExp([
  '\\bnew\\b', 'confirm', 'repeat', 'retype', 're ?enter', 'again', 'verify', 'create', 'choose',
  'neu', 'bestätig', 'wiederhol', 'nouveau', 'nouvelle', 'confirmer', 'répéter', 'nuevo', 'nueva',
  'repetir', 'confirmar', 'nuovo', 'nuova', 'ripeti', 'conferma', 'nieuw', 'herhaal', 'bevestig',
  'nowe', 'powtórz', 'новый', 'повтор', '新しい', '确认', '確認', '新',
  '\\bnova\\b', '\\bnovo\\b', '\\bny\\b', '\\bnytt\\b', 'bekreft', 'gjenta', '\\bbaru\\b', 'ulangi', 'नया', 'नई', 'पुष्टि',
  '새 ?비밀번호', '재입력',
].join('|'), 'i');

const CURRENT_PASSWORD_RE = new RegExp([
  'current', '\\bold\\b', 'existing', 'present', 'aktuell', 'bisherig', '\\balt(es)?\\b', 'actuel',
  'ancien', 'actual', 'anterior', 'attuale', 'vecchia', 'huidig', 'oud', 'obecne', 'текущ', 'стар',
  '現在', '当前', '旧', '\\batual\\b', 'nåværende', '\\bgammelt?\\b', '\\blama\\b', '현재', 'वर्तमान',
].join('|'), 'i');

const SIGNUP_TEXT_RE = new RegExp([
  'sign ?up', 'register', 'registration', 'create (an |your )?account', 'join', 'get started',
  'registrier', 'konto erstellen', 'créer (un )?compte', 'inscri', 'crear (una )?cuenta', 'regístr',
  'crea (un )?account', 'registreren', 'zarejestruj', 'регистрац', '新規登録', '注册', '註冊', '가입',
  'アカウント作成', 'साइन अप', 'पंजीकरण', 'खाता बनाएं', 'खाता बनाएँ', '\\bdaftar\\b', 'buat akun',
  'criar (uma )?conta', 'cadastr', 'registrer', 'ny bruker', 'opprett (en )?(ny )?(konto|bruker)', 'bli kunde',
].join('|'), 'i');

const LOGIN_TEXT_RE = new RegExp([
  'sign ?in', 'log ?in', 'log ?on', 'anmelden', 'einloggen', 'connexion', 'se connecter',
  'iniciar sesión', 'acceder', 'entrar', 'accedi', 'inloggen', 'zaloguj', 'войти', 'ログイン', 'サインイン',
  '登录', '登入', '로그인', 'लॉग इन', 'लॉगिन', 'साइन इन', '\\bmasuk\\b', 'iniciar sessão', 'logg (inn|på)',
].join('|'), 'i');

const FORGOT_WORDS = [
  'forgot', 'vergessen', 'oublié', 'olvid', 'esqueceu', 'dimenticat', 'vergeten', 'zapomnia', 'забыли', 'glemt',
  'lupa (kata sandi|sandi)', 'भूल गए', '忘れ', '忘记', '忘記', '잊으셨', '비밀번호 찾기',
];

const ACCOUNT_WORDING_RE = new RegExp([LOGIN_TEXT_RE.source, SIGNUP_TEXT_RE.source, ...FORGOT_WORDS].join('|'), 'i');

// A form saying these is no sign-in, whatever its one password field is called.
const SETS_PASSWORD_RE = new RegExp([
  '(create|choose|set( up)?|pick|make) (a |an |your )?(new |strong |secure )?password', 'confirm', 'repeat', 'retype',
  '\\bre ?enter', '\\breset\\b', '(change|update) (your |the )?password',
  'passwort (erstellen|festlegen|wählen|ändern)', 'bestätig', 'wiederhol', 'zurücksetzen',
  '(créer|choisir|définir|changer|modifier) (un |votre |le )?mot de passe', 'confirmer', 'répéter', 'réinitialis',
  '(crear|elegir|establecer|cambiar) (una |tu |la )?contraseña', 'repetir', 'confirmar', 'restablecer',
  '(criar|definir|alterar|mudar) (uma |sua |a )?senha', 'redefinir',
  '(crea|scegli|imposta|modifica|cambia) (una |la )?password', 'conferma', 'ripeti', 'reimposta',
  'wachtwoord (aanmaken|kiezen|instellen|wijzigen)', 'herhaal', 'bevestig', 'herstel',
  '(utwórz|ustaw|zmień) hasło', 'powtórz', 'resetuj',
  '(создайте|придумайте|задайте|изменить|смените) пароль', 'повтор', 'сброс',
  '(opprett|velg|lag|endre) (et |nytt )?passord', 'bekreft', 'gjenta', 'tilbakestill',
  'パスワード(の)?(変更|設定|再設定)', '確認', 'リセット', '(设置|修改|重置|更改)密码', '(設定|修改|重設|更改)密碼', '确认', '重置',
  '비밀번호 (변경|설정|재설정)', '재입력', '재설정', 'पासवर्ड (बनाएं|बदलें|रीसेट)', 'पुष्टि',
  '(buat|ubah|atur ulang) kata sandi', 'konfirmasi', 'ulangi',
].join('|'), 'i');

// A page whose one password field says "new password" is a reset.
const NEW_PASSWORD_PHRASE_RE = /\bnew password|neues passwort|nouveau mot de passe|nueva contraseña|nova senha|nuova password|nieuw wachtwoord|nowe hasło|новый пароль|nytt passord|新しいパスワード|新密码|新密碼|새 비밀번호|नया पासवर्ड|kata sandi baru/i;

const OTHER_ACTION_RE = new RegExp([
  '\\b(publish|save|update|post|send|search|apply|add|create|upload|schedule|preview|draft|comment|reply|subscribe|checkout|pay|buy|order|delete|remove|filter)\\b',
  '\\b(speichern|veröffentlichen|aktualisieren|suchen|senden|hinzufügen|enregistrer|publier|mettre à jour|rechercher|envoyer|ajouter)\\b',
  '\\b(guardar|publicar|actualizar|buscar|enviar|añadir|agregar|simpan|terbitkan|perbarui|cari|kirim|tambah)\\b',
  'सहेजें', 'प्रकाशित', 'खोजें', 'भेजें', 'जोड़ें', 'अपडेट', '保存', '公開', '更新', '検索', '送信', '追加', '投稿',
  '저장', '게시', '발행', '업데이트', '검색', '보내기', '추가', '儲存', '发布', '發布', '搜索', '搜尋', '发送', '傳送', '添加', '新增',
].join('|'), 'i');

const EDITOR_WORDING_RE = /publish|\bvisibility\b|\bdraft\b|veröffentl|sichtbarkeit|\bentwurf\b|\bpublier\b|publication|visibilité|brouillon|\bpublicar\b|visibilidad|borrador|\bterbit|visibilitas|\bdraf\b|प्रकाशित|公開|投稿|下書き|게시|발행|공개|发布|發布|草稿|可见性|可見度/i;

// A password protecting a post, page, file or room rather than signing in.
const PROTECTS_HINTS_RE = /protect|\b(post|page|article|album|gallery|file|folder|document|pdf|zip|archive|share|sharing|room|meeting|wi ?fi|ssid|network|blog|survey)\b|\bpost ?pass|\bvisibility\b|geschützt|schützen|\bbeitrag|\bseite\b|sichtbarkeit|protég|visibilité|proteg|visibilidad|lindungi|visibilitas|\bhalaman\b|\btulisan\b|सुरक्षित|पोस्ट|पृष्ठ|保護|投稿|公開|보호|게시물|공개|保护|文章|可见|可見/i;
const ACCOUNT_HINTS_RE = /user|log ?in|sign ?in|account|e ?mail|benutzer|konto|utilisateur|compte|usuario|cuenta|pengguna|akun|ユーザ|ログイン|用户|用戶|账号|帳號|登录|登入|사용자|계정|로그인|उपयोगकर्ता|खाता|लॉगिन/i;
const PROTECTS_NEAR_RE = /password ?protect|protected by (a )?password|protect (this|the) (post|page|article|file|document)|\bvisibility\b|passwort ?geschützt|sichtbarkeit|protégé par (un )?mot de passe|visibilité|proteg(ido|ida) (con|por) contraseña|visibilidad|dilindungi kata sandi|visibilitas|पासवर्ड से सुरक्षित|パスワード保護|公開状態|비밀번호 보호|공개 범위|密码保护|密碼保護|可见性|可見度/i;

export function normalizeHint(text) {
  if (!text) return '';
  return String(text)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[_\-.:[\]/\\#()*"'|,;]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function autocompleteTokens(el) {
  const raw = el.getAttribute('autocomplete') || '';
  return raw.toLowerCase().split(/\s+/).filter(Boolean);
}

function textOf(node, max = 200) {
  return (node?.textContent || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

const LINK_SEL = 'a, [role=link]';

// The text of `node` without its links: "Create account" on a sign-in form leads elsewhere.
function ownTextOf(node, max = 1500) {
  if (!node?.querySelector?.(LINK_SEL)) return textOf(node, max);
  const doc = node.ownerDocument || node;
  const walker = doc.createTreeWalker(node, 4 /* NodeFilter.SHOW_TEXT */);
  const parts = [];
  let length = 0;
  for (let t = walker.nextNode(); t && length < max; t = walker.nextNode()) {
    const link = t.parentElement?.closest?.(LINK_SEL);
    if (link && node.contains(link)) continue;
    parts.push(t.data);
    length += t.data.length;
  }
  return parts.join(' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function rootOf(el) {
  return typeof el.getRootNode === 'function' ? el.getRootNode() : el.ownerDocument;
}

export function labelText(el) {
  const parts = [];
  try {
    if (el.labels) for (const label of el.labels) parts.push(textOf(label));
  } catch { /* some elements throw on .labels */ }
  const root = rootOf(el);
  if (!parts.length && el.id && root?.querySelectorAll) {
    try {
      for (const label of root.querySelectorAll(`label[for="${cssEscape(el.id)}"]`)) parts.push(textOf(label));
    } catch { /* invalid selector */ }
  }
  const closestLabel = el.closest?.('label');
  if (closestLabel && !parts.length) parts.push(textOf(closestLabel));
  const labelledBy = el.getAttribute('aria-labelledby');
  if (labelledBy && root?.getElementById) {
    for (const id of labelledBy.split(/\s+/)) {
      const ref = root.getElementById(id);
      if (ref) parts.push(textOf(ref));
    }
  }
  return parts.filter(Boolean).join(' ');
}

function cssEscape(s) {
  if (globalThis.CSS?.escape) return globalThis.CSS.escape(s);
  return String(s).replace(/["\\]/g, '\\$&');
}

// Per-pass hint cache (fields are classified several times); dropped after so relabelled fields are re-read.
let hintCache = null;

function withHintCache(fn) {
  if (hintCache) return fn();
  hintCache = new Map();
  try { return fn(); } finally { hintCache = null; }
}

function fieldHints(el) {
  const cached = hintCache?.get(el);
  if (cached !== undefined) return cached;
  const attrs = ['name', 'id', 'placeholder', 'aria-label', 'title', 'data-testid', 'formcontrolname', 'ng-model', 'v-model']
    .map((a) => el.getAttribute(a) || '');
  const hints = normalizeHint([...attrs, labelText(el)].join(' '));
  hintCache?.set(el, hints);
  return hints;
}

function inputType(el) {
  return (el.getAttribute('type') || '').toLowerCase();
}

export function isFillableInput(el) {
  if (!el || el.tagName !== 'INPUT') return false;
  if (!FILLABLE_TYPES.has(inputType(el))) return false;
  if (el.disabled || el.readOnly) return false;
  return true;
}

// No layout needed, so it works under jsdom and as a cheap first pass in the browser.
export function isVisibleNoLayout(el) {
  if (!el?.isConnected) return false;
  if (inputType(el) === 'hidden') return false;
  const view = el.ownerDocument?.defaultView;
  let node = el;
  while (node && node.nodeType === 1) {
    if (node.hidden) return false;
    if (node.getAttribute?.('aria-hidden') === 'true' && node === el) return false;
    const cs = view?.getComputedStyle?.(node);
    if (cs) {
      if (cs.display === 'none') return false;
      if (node === el && (cs.visibility === 'hidden' || cs.visibility === 'collapse')) return false;
      if (cs.opacity !== '' && Number(cs.opacity) < 0.05) return false;
    }
    node = node.parentElement || node.getRootNode?.()?.host || null;
  }
  return true;
}

export function isVisible(el) {
  if (!isVisibleNoLayout(el)) return false;
  if (typeof el.checkVisibility === 'function' &&
      !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width < 4 || rect.height < 4) return false;
  const view = el.ownerDocument.defaultView;
  const sx = view?.scrollX || 0;
  const sy = view?.scrollY || 0;
  // Honeypots are often positioned at -9999px.
  if (rect.right + sx < 0 || rect.bottom + sy < 0) return false;
  return true;
}

export function collectInputs(root) {
  const out = [];
  const walk = (r) => {
    for (const el of r.querySelectorAll('*')) {
      if (el.tagName === 'INPUT') out.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(root);
  return out;
}

function formOf(el) {
  if (el.form) return el.form;
  let node = el;
  while (node) {
    const f = node.closest?.('form');
    if (f) return f;
    node = node.getRootNode?.()?.host || null;
  }
  return null;
}

function maxLength(el) {
  const v = el.getAttribute('maxlength');
  if (v === null) return null;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function looksNumericCode(el) {
  const ml = maxLength(el);
  const inputmode = (el.getAttribute('inputmode') || '').toLowerCase();
  const pattern = el.getAttribute('pattern') || '';
  const type = inputType(el);
  if (ml !== null && ml >= 4 && ml <= 10) return true;
  if (inputmode === 'numeric' || inputmode === 'decimal') return true;
  if (/\\d|\[0-9\]/.test(pattern)) return true;
  if (type === 'number' || type === 'tel') return true;
  return false;
}

// One-time-code score (0 = no); weak hints count when `contextText` (string or lazy fn) mentions 2FA.
export function otpScore(el, contextText = '') {
  const ac = autocompleteTokens(el);
  if (ac.includes('one-time-code')) return 100;
  if (ac.some((t) => t.startsWith('cc-') || t === 'postal-code' || t === 'username' || t === 'email' || t === 'tel')) return 0;
  const hints = fieldHints(el);
  if (OTP_NEGATIVE_RE.test(hints)) return 0;
  const type = inputType(el);
  if (OTP_STRONG_RE.test(hints)) {
    // A password-typed field needs an unambiguous OTP name ("verify" alone means "confirm password").
    if (type === 'password' && !/\b(otp|totp|2 ?fa|mfa|one ?time|two ?factor|authenticator|passcode)\b/i.test(hints)) return 0;
    return 80;
  }
  if (type === 'password' || type === 'email') return 0;
  if (OTP_WEAK_RE.test(hints)) {
    const numeric = looksNumericCode(el);
    const ctx = contextLooksLike2fa(typeof contextText === 'function' ? contextText() : contextText);
    if (numeric && ctx) return 70;
    if (numeric || ctx) return 50;
  }
  return 0;
}

export function contextLooksLike2fa(text) {
  if (!text) return false;
  return OTP_STRONG_RE.test(normalizeHint(text)) || /\bauthenticator\b|\bverification\b|\b2fa\b/i.test(text) ||
    looksLike2faPage(text);
}

const PHONE_RE = /\b(phone|mobile|cell|handy|telefon|téléphone|teléfono|telefono|телефон|電話|手机)\b/i;

export function couldBeCodeField(el) {
  if (!isFillableInput(el)) return false;
  const type = inputType(el);
  if (type === 'password' || type === 'email') return false;
  const ac = autocompleteTokens(el);
  if (ac.includes('one-time-code')) return true;
  if (el.getAttribute('role') === 'combobox' || el.hasAttribute('list') || el.getAttribute('aria-autocomplete') === 'list') return false;
  if (ac.some((t) => t.startsWith('cc-') || t.startsWith('address') || t.startsWith('tel') ||
      ['username', 'email', 'postal-code', 'name', 'given-name', 'family-name', 'new-password', 'current-password'].includes(t))) return false;
  const hints = fieldHints(el);
  return !OTP_NEGATIVE_RE.test(hints) && !PHONE_RE.test(hints) && !notCodeField(hints);
}

function codeShaped(el) {
  const ml = maxLength(el);
  const inputmode = (el.getAttribute('inputmode') || '').toLowerCase();
  const type = inputType(el);
  const digits = inputmode === 'numeric' || type === 'tel' || type === 'number' || /\\d|\[0-9\]/.test(el.getAttribute('pattern') || '');
  if (ml !== null && (ml < 4 || ml > 10)) return false;
  return digits || ml !== null;
}

// An unnamed field's 2FA-ness is read from its surroundings, never the whole page: an inbox listing
// "Your verification code" says nothing about its Subject box.

const NEAR_TEXT_MAX = 600;
const NEAR_INPUTS_MAX = 4;
export const SHORT_PAGE_TEXT = 3000;
const SHORT_PAGE_INPUTS = 3;

function textInputCount(node) {
  let n = 0;
  for (const el of node.querySelectorAll('input')) if (FILLABLE_TYPES.has(inputType(el))) n++;
  return n;
}

function parentAcrossShadow(node) {
  return node.parentElement || node.getRootNode?.()?.host || null;
}

function nearBox(el) {
  let best = null;
  let node = parentAcrossShadow(el);
  for (let depth = 0; node && node.nodeType === 1 && depth < 12; depth++) {
    const raw = node.textContent || '';
    if (raw.length > NEAR_TEXT_MAX * 4) break;
    const t = raw.replace(/\s+/g, ' ').trim();
    if (t.length > NEAR_TEXT_MAX || textInputCount(node) > NEAR_INPUTS_MAX) break;
    best = node;
    if (node === node.ownerDocument?.body) break;
    node = parentAcrossShadow(node);
  }
  return best;
}

export function nearText(el) {
  const box = nearBox(el);
  const best = box ? (box.textContent || '').replace(/\s+/g, ' ').trim() : '';
  return `${el.tagName === 'INPUT' ? labelText(el) : ''} ${best}`.trim();
}

function nearContext(el) {
  const form = el.tagName === 'INPUT' ? formOf(el) : null;
  const buttons = form && textInputCount(form) <= NEAR_INPUTS_MAX ? submitTextOf(form) : '';
  return `${nearText(el)} ${buttons}`.trim();
}

const RICH_EDITOR_SEL = 'textarea, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]:not(input)';

// Inputs next to a compose window, chat or comment box are To / Subject / title boxes, never a code.
export function nearRichEditor(el) {
  if (el.closest?.('[contenteditable]:not([contenteditable="false"])')) return true;
  let top = null;
  let node = parentAcrossShadow(el);
  for (let depth = 0; node && node.nodeType === 1 && depth < 6; depth++) {
    if (node === node.ownerDocument?.body) break;
    top = node;
    node = parentAcrossShadow(node);
  }
  if (!top?.querySelectorAll) return false;
  for (const ed of top.querySelectorAll(RICH_EDITOR_SEL)) {
    if (ed !== el && isVisibleNoLayout(ed)) return true;
  }
  return false;
}

/** Only on a short page like this may page text (not the surroundings) make a code-shaped field the code field. */
function looksLikeShort2faPage(text, inputCount) {
  return !!text && text.length <= SHORT_PAGE_TEXT && inputCount <= SHORT_PAGE_INPUTS && looksLike2faPage(text);
}

// Fallback without a named OTP field: a code-shaped field, or the form's lone text input, with 2FA wording nearby.
function unnamedOtpField(inputs, near, shortPage2fa) {
  if (inputs.some((el) => inputType(el) === 'password')) return null;
  const cands = inputs.filter((el) => couldBeCodeField(el) && !autocompleteTokens(el).includes('webauthn') &&
    !USER_RE.test(fieldHints(el)));
  if (!cands.length) return null;
  for (const el of cands.filter(codeShaped)) {
    if (nearRichEditor(el)) continue;
    if (contextLooksLike2fa(near(el)) || shortPage2fa()) return el;
  }
  const lone = inputs.length === 1 && cands.length === 1 ? cands[0] : null;
  if (lone && !nearRichEditor(lone) && contextLooksLike2fa(near(lone))) return lone;
  return null;
}

/** With a pending 2FA code on offer, may the focused unnamed field `el` take it? */
export function adoptableCodeField(el, { pageText = () => '', inputCount = () => 0, loginPath = false } = {}) {
  if (!couldBeCodeField(el) || el.value) return false;
  if (autocompleteTokens(el).includes('one-time-code')) return true;
  if (nearRichEditor(el)) return false;
  const hints = fieldHints(el);
  if (OTP_STRONG_RE.test(hints) || OTP_WEAK_RE.test(hints)) return true;
  if (USER_RE.test(hints)) return false;
  if (codeShaped(el)) return true;
  if (contextLooksLike2fa(nearContext(el))) return true;
  const text = pageText() || '';
  if (text.length > SHORT_PAGE_TEXT || inputCount() > SHORT_PAGE_INPUTS) return false;
  return loginPath || looksLike2faPage(text);
}

/** Named just "ID" (common on Korean and Japanese sites). */
function namedJustId(el) {
  return ['name', 'id', 'placeholder', 'aria-label'].some((a) => normalizeHint(el.getAttribute(a)) === 'id') ||
    normalizeHint(labelText(el)) === 'id';
}

export function usernameScore(el) {
  const type = inputType(el);
  if (type === 'password') return 0;
  const ac = autocompleteTokens(el);
  if (ac.includes('username')) return 100;
  if (ac.some(notLoginToken)) return 0;
  if (ac.includes('email')) return 70;
  if (ac.includes('webauthn')) return 60;
  if (el.closest?.('[contenteditable]:not([contenteditable="false"])')) return 0;
  const hints = fieldHints(el);
  if (notUsernameHints(hints)) return 0;
  if (type === 'email') return 60;
  if (USERNAME_WORDS_RE.test(hints) || namedJustId(el)) return 50;
  if (ac.includes('tel') || ac.includes('tel-national') || PHONE_LOGIN_RE.test(hints)) return 25;
  return 0;
}

function passwordHint(el) {
  const ac = autocompleteTokens(el);
  if (ac.includes('new-password')) return FieldKind.NEW_PASSWORD;
  if (ac.includes('current-password')) return FieldKind.CURRENT_PASSWORD;
  const hints = fieldHints(el);
  if (CURRENT_PASSWORD_RE.test(hints)) return FieldKind.CURRENT_PASSWORD;
  if (NEW_PASSWORD_RE.test(hints)) return FieldKind.NEW_PASSWORD;
  return null;
}

const SIGNUP_PATH_RE = /(sign[-_ ]?up|register|registrer|registration|join|create[-_ ]?account|new[-_ ]?account|enrol)/i;
const LOGIN_PATH_RE = /(log[-_ ]?in|sign[-_ ]?in|log[-_ ]?on|logg[-_ ]?inn|session)/i;

/** 'signup' | 'login' | null. Submit text wins (a sign-up form often links "Log in"), then form text, then path. */
export function formIntent({ text = '', submitText = '', path = '' } = {}) {
  const decide = (t) => {
    const s = SIGNUP_TEXT_RE.test(t);
    const l = LOGIN_TEXT_RE.test(t);
    if (s && !l) return 'signup';
    if (l && !s) return 'login';
    return null;
  };
  return decide(normalizeHint(submitText)) || decide(normalizeHint(text)) ||
    (SIGNUP_PATH_RE.test(path) && !LOGIN_PATH_RE.test(path) ? 'signup' : null);
}

function submitTextOf(container) {
  if (!container?.querySelectorAll) return '';
  const buttons = [...container.querySelectorAll('button, input[type=submit], input[type=button], [role=button]')];
  const isSubmit = (b) => {
    const type = (b.getAttribute('type') || '').toLowerCase();
    return type === 'submit' || (b.tagName === 'BUTTON' && !type && !!b.closest('form'));
  };
  const chosen = buttons.some(isSubmit) ? buttons.filter(isSubmit) : buttons;
  return chosen.slice(0, 4)
    .map((b) => `${b.textContent || ''} ${b.getAttribute('value') || ''} ${b.getAttribute('aria-label') || ''}`)
    .join(' ').replace(/\s+/g, ' ').trim().slice(0, 300);
}

/** Password kinds: explicit hints, then count and intent. `groupText`: form text or `{ intent }`. */
export function classifyPasswords(els, groupText = '') {
  const kinds = els.map(passwordHint);
  const signup = typeof groupText === 'object' && groupText !== null
    ? groupText.intent === 'signup'
    : formIntent({ text: groupText }) === 'signup';
  if (els.length === 1) {
    if (!kinds[0]) kinds[0] = signup ? FieldKind.NEW_PASSWORD : FieldKind.CURRENT_PASSWORD;
  } else if (els.length === 2) {
    if (kinds[0] === FieldKind.CURRENT_PASSWORD && !kinds[1]) kinds[1] = FieldKind.NEW_PASSWORD;
    else if (kinds[1] === FieldKind.CURRENT_PASSWORD && !kinds[0]) kinds[0] = FieldKind.NEW_PASSWORD;
    else if (kinds[1] === FieldKind.NEW_PASSWORD && !kinds[0]) kinds[0] = signup || NEW_PASSWORD_RE.test(fieldHints(els[1])) ? FieldKind.NEW_PASSWORD : FieldKind.CURRENT_PASSWORD;
    for (let i = 0; i < 2; i++) if (!kinds[i]) kinds[i] = FieldKind.NEW_PASSWORD;
  } else {
    let haveCurrent = kinds.includes(FieldKind.CURRENT_PASSWORD);
    for (let i = 0; i < kinds.length; i++) {
      if (kinds[i]) continue;
      if (!haveCurrent && !signup) { kinds[i] = FieldKind.CURRENT_PASSWORD; haveCurrent = true; } else kinds[i] = FieldKind.NEW_PASSWORD;
    }
  }
  return kinds;
}

// Split OTP boxes: strict ones (maxlength/size 1) by attributes and DOM adjacency, loose ones
// (script-limited) only by layout, so never without layout.

const BOX_TYPES = new Set(['', 'text', 'tel', 'number', 'password']);
const DEEP_BOX_LEVELS = 8;

const NOT_CODE_BOX_HINT_RE = new RegExp([
  '\\b(phone|mobile|telefon|téléphone|teléfono|telefono|телефон|電話|手机)\\b',
  '\\b(date|day|month|year|dd|mm|yy|yyyy|birth|birthday|dob)\\b', '\\b(jour|mois|année|monat|jahr|día|mes|año)\\b',
].join('|'), 'i');
const NOT_CODE_BOX_CONTEXT_RE = /\b(card ?number|credit ?card|debit ?card|expir\w*|date of birth|birth ?date|birthday|dob|captcha|product ?key|licen[cs]e ?key|serial ?number)\b/i;
// Loose boxes next to PIN wording without 2FA wording are a PIN pad.
const PIN_RE = /\bpin\b/i;

/** The rendered box of `el`, or null without layout; tests stub it through `rectOf`. */
export function boxRect(el) {
  try {
    const r = el.getBoundingClientRect?.();
    if (r && r.width > 0 && r.height > 0) return { left: r.left, top: r.top, width: r.width, height: r.height };
  } catch { /* detached or foreign element */ }
  return null;
}

export function narrowBox(r) {
  return !!r && r.height >= 12 && r.width >= 8 && r.width <= r.height * 3;
}

export function sameSizeBoxes(a, b) {
  return !!a && !!b && Math.abs(a.width - b.width) <= 4 && Math.abs(a.height - b.height) <= 4;
}

export function nextOnRow(a, b) {
  if (!a || !b) return false;
  const dy = Math.abs((a.top + a.height / 2) - (b.top + b.height / 2));
  if (dy > Math.max(4, Math.min(a.height, b.height) / 4)) return false;
  const gap = b.left - (a.left + a.width);
  return gap >= -2 && gap <= Math.max(a.width, b.width) * 2.5 + 16;
}

function isSingleCharBox(el) {
  if (!BOX_TYPES.has(inputType(el))) return false;
  return maxLength(el) === 1 || el.getAttribute('size') === '1';
}

function boxesAdjacent(a, b) {
  let pa = parentAcrossShadow(a);
  let pb = parentAcrossShadow(b);
  for (let depth = 0; depth < 3 && pa && pb; depth++) {
    if (pa === pb) return true;
    pa = parentAcrossShadow(pa);
    pb = parentAcrossShadow(pb);
  }
  return false;
}

function meetWithin(a, b, limit) {
  const above = new Set();
  let n = parentAcrossShadow(a);
  for (let d = 0; n && d < limit; d++, n = parentAcrossShadow(n)) above.add(n);
  n = parentAcrossShadow(b);
  for (let d = 0; n && d < limit; d++, n = parentAcrossShadow(n)) if (above.has(n)) return true;
  return false;
}

// Like nearBox but not counting the boxes themselves, which would exceed NEAR_INPUTS_MAX for long runs.
function runNearText(els) {
  let node = commonBox(els[0], els[els.length - 1]);
  let best = null;
  for (let depth = 0; node && node.nodeType === 1 && depth < 8; depth++) {
    const raw = node.textContent || '';
    if (raw.length > NEAR_TEXT_MAX * 4) break;
    if (raw.replace(/\s+/g, ' ').trim().length > NEAR_TEXT_MAX) break;
    if (node.querySelectorAll && textInputCount(node) - els.length > NEAR_INPUTS_MAX) break;
    best = node;
    if (node === node.ownerDocument?.body) break;
    node = parentAcrossShadow(node);
  }
  return best ? (best.textContent || '').replace(/\s+/g, ' ').trim() : '';
}

function boxCandidate(el, rectOf) {
  if (!BOX_TYPES.has(inputType(el))) return null;
  const strict = isSingleCharBox(el);
  const ml = strict ? 1 : maxLength(el);
  if (!strict && ml !== null && ml !== 2) return null;
  let rect = null;
  try { rect = rectOf(el) || null; } catch { rect = null; }
  if (!strict && !narrowBox(rect)) return null;
  return { el, strict, ml, rect };
}

function boxFollows(p, m) {
  if (p.strict && m.strict && boxesAdjacent(p.el, m.el)) return true;
  if (!sameSizeBoxes(p.rect, m.rect) || !nextOnRow(p.rect, m.rect)) return false;
  return meetWithin(p.el, m.el, DEEP_BOX_LEVELS);
}

// Whether a run of 4-8 boxes is one code entry. Loose runs of exactly four need OTP evidence (a card
// number in 4 boxes); maxlength=2 boxes too.
function splitRunIsOtp(run, contextTextFor) {
  const els = run.map((m) => m.el);
  const hints = els.map(fieldHints).join(' ');
  if (OTP_NEGATIVE_RE.test(hints)) return false;
  const acs = els.flatMap(autocompleteTokens);
  const named = acs.includes('one-time-code') || OTP_STRONG_RE.test(hints);
  if (!named && NOT_CODE_BOX_HINT_RE.test(hints)) return false;
  if (acs.some((t) => t.startsWith('cc-') || t.startsWith('tel') || t.startsWith('bday') || t === 'postal-code')) return false;
  // Placeholders D D M M Y Y Y Y (J J M M A A A A): a date typed digit by digit.
  const ph = els.map((el) => (el.getAttribute('placeholder') || '').trim()).join('');
  if (/^[dmyja]{4,8}$/i.test(ph) && /[dmj]/i.test(ph) && /[ya]/i.test(ph)) return false;
  let ctxCache = null;
  const ctx = () => (ctxCache ??= `${contextTextFor(els[0]) || ''} ${runNearText(els)}`);
  const strong = () => named || contextLooksLike2fa(ctx());
  const numeric = els.every(looksNumericCodeBox);
  if (run.every((m) => m.strict)) {
    if (strong()) return true;
    if (NOT_CODE_BOX_CONTEXT_RE.test(ctx())) return false;
    return numeric || els.length === 6;
  }
  if (!run.every((m) => m.rect && sameSizeBoxes(run[0].rect, m.rect))) return false;
  if (strong()) return true;
  if (run.some((m) => m.ml === 2) || els.length === 4) return false;
  if (NOT_CODE_BOX_CONTEXT_RE.test(ctx()) || PIN_RE.test(ctx()) || PIN_RE.test(hints)) return false;
  return numeric || els.length === 6;
}

/** Runs of 4-8 one-character boxes forming one OTP entry. `inputs` must be in document order. */
export function findSplitOtpGroups(inputs, contextTextFor = () => '', { rectOf = boxRect } = {}) {
  const groups = [];
  let run = [];
  const flush = () => {
    if (run.length >= 4 && run.length <= 8 && splitRunIsOtp(run, contextTextFor)) groups.push(run.map((m) => m.el));
    run = [];
  };
  for (const el of inputs) {
    const m = boxCandidate(el, rectOf);
    if (!m) { flush(); continue; }
    if (run.length && !boxFollows(run[run.length - 1], m)) flush();
    run.push(m);
  }
  flush();
  return groups;
}

function looksNumericCodeBox(el) {
  const inputmode = (el.getAttribute('inputmode') || '').toLowerCase();
  const type = inputType(el);
  const pattern = el.getAttribute('pattern') || '';
  return inputmode === 'numeric' || type === 'tel' || type === 'number' || /\\d|\[0-9\]/.test(pattern);
}

/**
 * A see-through code input under boxes drawn by divs (input-otp, shadcn/ui InputOTP). Needs a real
 * rendered size and OTP evidence, and is only ever the OTP field, so a see-through login honeypot stays out.
 */
export function isTransparentOtpInput(el, rectOf = boxRect) {
  if (!isFillableInput(el) || !el.isConnected) return false;
  const type = inputType(el);
  if (type === 'password' || type === 'email') return false;
  const ac = autocompleteTokens(el);
  const hints = fieldHints(el);
  if (OTP_NEGATIVE_RE.test(hints)) return false;
  if (ac.some((t) => t.startsWith('cc-') || ['username', 'email', 'current-password', 'new-password'].includes(t))) return false;
  const ml = maxLength(el);
  const evidence = ac.includes('one-time-code') || OTP_STRONG_RE.test(hints) ||
    (ml !== null && ml >= 4 && ml <= 8 && looksNumericCodeBox(el));
  if (!evidence) return false;
  const view = el.ownerDocument?.defaultView;
  let seeThrough = false;
  for (let node = el; node && node.nodeType === 1; node = parentAcrossShadow(node)) {
    if (node.hidden) return false;
    const cs = view?.getComputedStyle?.(node);
    if (!cs) continue;
    if (cs.display === 'none') return false;
    if (node === el) {
      if (cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
      const color = (cs.color || '').replace(/\s+/g, '').toLowerCase();
      if (color === 'transparent' || /^rgba\(\d+,\d+,\d+,0(\.0+)?\)$/.test(color)) seeThrough = true;
    }
    if (cs.opacity !== '' && Number(cs.opacity) < 0.05) seeThrough = true;
  }
  if (!seeThrough) return false;
  let r = null;
  try { r = rectOf(el); } catch { r = null; }
  if (!r || r.width < 20 || r.height < 12) return false;
  const sx = view?.scrollX || 0;
  const sy = view?.scrollY || 0;
  return r.left + r.width + sx > 0 && r.top + r.height + sy > 0;
}

function lowestCommonAncestor(els) {
  if (!els.length) return null;
  let anc = els[0].parentElement;
  while (anc && !els.every((e) => anc.contains(e))) anc = anc.parentElement;
  return anc;
}

// Other fields that make a form busy unless it reads as a sign-in; TOO_MANY_FIELDS even then.
const BUSY_FIELDS = 3;
const TOO_MANY_FIELDS = 6;
const MAX_PLAIN_CONTROLS = 6;
const FORMLESS_BOX_TEXT = 2000;

const BUTTON_TYPES = new Set(['button', 'submit', 'reset', 'image', 'checkbox', 'radio']);
const CAPTCHA_RESPONSE_RE = /captcha-response/i;

function commonBox(a, b) {
  const above = new Set();
  for (let n = parentAcrossShadow(a); n; n = parentAcrossShadow(n)) above.add(n);
  for (let n = parentAcrossShadow(b); n; n = parentAcrossShadow(n)) if (above.has(n)) return n;
  return null;
}

function boxControls(box, visible) {
  const out = { text: [], other: 0, rich: false, clicks: 0 };
  const walk = (root) => {
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walk(el.shadowRoot);
      const tag = el.tagName;
      if (tag === 'INPUT') {
        const type = inputType(el);
        if (type === 'hidden' || type === 'password') continue;
        if (BUTTON_TYPES.has(type)) out.clicks++;
        else if (!visible(el)) continue;
        else if (isFillableInput(el)) out.text.push(el);
        else out.other++;
      } else if (tag === 'SELECT') {
        if (visible(el)) out.other++;
      } else if (tag === 'TEXTAREA') {
        if (!CAPTCHA_RESPONSE_RE.test(`${el.name} ${el.id} ${el.className}`) && visible(el)) out.rich = true;
      } else if (tag === 'BUTTON' || el.getAttribute('role') === 'button') {
        out.clicks++;
      } else if (((el.hasAttribute('contenteditable') && el.getAttribute('contenteditable') !== 'false') || el.getAttribute('role') === 'textbox') && visible(el)) {
        out.rich = true;
      }
    }
  };
  if (box) walk(box);
  return out;
}

/** @returns {'login' | 'other' | null} buttons first, then the text next to the field */
function formWording(pw, g) {
  const actions = normalizeHint(submitTextOf(g.form || nearBox(pw)));
  if (ACCOUNT_WORDING_RE.test(actions)) return 'login';
  if (OTHER_ACTION_RE.test(actions)) return 'other';
  const near = normalizeHint(`${g.small ? g.text : ''} ${nearText(pw)}`);
  if (ACCOUNT_WORDING_RE.test(near)) return 'login';
  return EDITOR_WORDING_RE.test(near) ? 'other' : null;
}

// A field with username evidence doesn't count in a busy box (settings page, editor). The box is the
// smallest element holding both fields, so a login box inside a whole-page form is judged on its own.
function usernameBacked(el, pw, g, otpEls, visible) {
  const ac = autocompleteTokens(el);
  if (ac.includes('username') || ac.includes('webauthn')) return true;
  if (g.newPasswords.length && !g.currentPassword) return true;
  const box = commonBox(el, pw);
  const inside = boxControls(box, visible);
  if (inside.rich) return false;
  if (!g.form && (box?.textContent || '').length > FORMLESS_BOX_TEXT) return false;
  const others = inside.other + inside.text.filter((x) => x !== el && !otpEls.has(x)).length;
  if (others > TOO_MANY_FIELDS) return false;
  return others < BUSY_FIELDS || formWording(pw, g) === 'login';
}

function visualLabel(el) {
  let node = el;
  for (let depth = 0; node && depth < 3; depth++) {
    let prev = node.previousSibling;
    while (prev && prev.nodeType !== 1 && !(prev.textContent || '').trim()) prev = prev.previousSibling;
    if (prev) {
      if (prev.nodeType === 1 && (/^H[1-3]$/.test(prev.tagName) || prev.querySelector?.('input, select, textarea'))) return '';
      const text = (prev.textContent || '').replace(/\s+/g, ' ').trim();
      return text.length <= 40 ? text : '';
    }
    node = node.parentElement;
  }
  return '';
}

// The classic unlabelled login form: one text input right before the password and nothing else in
// the box. The only case where a field without evidence is the username.
function anonymousUsername(el, pwEls, g, otpEls, visible) {
  const type = inputType(el);
  if (type !== '' && type !== 'text' && type !== 'tel') return false;
  if (autocompleteTokens(el).some(notLoginToken)) return false;
  if (el.getAttribute('role') === 'combobox' || el.hasAttribute('list') || el.getAttribute('aria-autocomplete') === 'list') return false;
  if (el.closest?.('[contenteditable]:not([contenteditable="false"])')) return false;
  const hints = fieldHints(el);
  if (notUsernameHints(hints) || notUsernameHints(normalizeHint(visualLabel(el)))) return false;
  if (pwEls.length > 1 && g.intent !== 'signup') return false;
  const pw = pwEls[0];
  const box = commonBox(el, pw);
  const inside = boxControls(box, visible);
  if (inside.rich || inside.other || inside.text.some((x) => x !== el && !otpEls.has(x))) return false;
  const wording = formWording(pw, g);
  if (wording === 'login') return true;
  if (wording === 'other' || BARE_NAME_RE.test(hints)) return false;
  const outer = g.form || g.container;
  const around = outer && outer !== box ? boxControls(outer, visible) : inside;
  if (around.rich || around.other + around.text.filter((x) => x !== el && !otpEls.has(x)).length >= BUSY_FIELDS) return false;
  return around.clicks <= MAX_PLAIN_CONTROLS;
}

function protectsContent(pw, g) {
  const hints = fieldHints(pw);
  const says = (PROTECTS_HINTS_RE.test(hints) && !ACCOUNT_HINTS_RE.test(hints)) || PROTECTS_NEAR_RE.test(normalizeHint(nearText(pw)));
  return says && formWording(pw, g) !== 'login';
}

// A `quiet` group (content-protecting or editor password, no sign-in around it) opens its menu only on
// request and is neither filled from elsewhere nor offered for saving.
function isQuietPassword(pwEls, g, otpEls, visible) {
  if (g.username || !pwEls.length) return false;
  if (pwEls.some((el) => protectsContent(el, g))) return true;
  if (pwEls.length !== 1) return false;
  const hint = passwordHint(pwEls[0]);
  if (hint === FieldKind.CURRENT_PASSWORD) return false;
  const wording = formWording(pwEls[0], g);
  if (wording === 'login') return false;
  const around = boxControls(g.form || g.container, visible);
  if (around.rich) return true;
  if (hint === FieldKind.NEW_PASSWORD) return false;
  return wording === 'other' || around.other + around.text.filter((x) => !otpEls.has(x)).length >= BUSY_FIELDS;
}

function formAttrs(form) {
  return form ? ['id', 'name', 'class', 'action'].map((a) => form.getAttribute(a) || '').join(' ') : '';
}

// Sites often mark a sign-in's only password as new-password. A form with just a username and that
// password, or the password alone, is treated as a sign-in unless something says otherwise.
function loneNewPasswordIsLogin(pw, rest, g, otpEls, visible) {
  if (g.intent === 'signup' || protectsContent(pw, g)) return false;
  const own = normalizeHint(g.ownText);
  if (g.intent !== 'login' && (SIGNUP_TEXT_RE.test(own) || SIGNUP_PATH_RE.test(formAttrs(g.form)))) return false;
  const hints = fieldHints(pw);
  if (SETS_PASSWORD_RE.test(hints) || SETS_PASSWORD_RE.test(own)) return false;
  if (formWording(pw, g) === 'other') return false;
  const around = boxControls(g.form || g.container, visible);
  if (around.rich || around.other) return false;
  const others = rest.filter((el) => el !== pw && !otpEls.has(el));
  if (!others.length) return !NEW_PASSWORD_RE.test(hints) && !NEW_PASSWORD_PHRASE_RE.test(own);
  if (others.length > 1) return false;
  const user = others[0];
  if (!(user.compareDocumentPosition(pw) & 4)) return false; // DOCUMENT_POSITION_FOLLOWING
  return usernameScore(user) > 0 || (g.intent === 'login' && !notUsernameHints(fieldHints(user)));
}

function groupContextText(container) {
  if (!container) return '';
  return textOf(container, 1500);
}

/**
 * Detects login-related fields under `root`, one group per form (or per root for form-less inputs).
 * @param {Document|ShadowRoot|Element} root
 * @param {{ isVisible?: (el: Element) => boolean, pageText?: () => string,
 *            rectOf?: (el: Element) => ({ left: number, top: number, width: number, height: number } | null) }} [opts]
 * @returns {{ groups: Group[], fields: Map<Element, {kind: string, group: Group}> }}
 * Group = { form, container, username, currentPassword, newPasswords, passwords, otp, text,
 *           intent: 'signup' | 'login' | null, quiet: boolean }
 *   otp = { kind: 'single' | 'split', fields: [el...] } | null
 */
export function detectFields(root, opts = {}) {
  return withHintCache(() => detectLoginFields(root, opts));
}

function detectLoginFields(root, { isVisible: visible = isVisible, pageText: readPageText = null, rectOf = boxRect } = {}) {
  let pageTextCache = null;
  const pageText = () => {
    if (pageTextCache === null) {
      try { pageTextCache = String(readPageText ? readPageText() : '').slice(0, 20_000); } catch { pageTextCache = ''; }
    }
    return pageTextCache;
  };
  const inputs = collectInputs(root).filter(isFillableInput);
  const all = inputs.filter((el) => visible(el));
  const shown = new Set(all);
  const ghosts = inputs.filter((el) => !shown.has(el) && isTransparentOtpInput(el, rectOf));
  const fields = new Map();
  const groupsByKey = new Map();

  const keyOf = (el) => formOf(el) || rootOf(el);
  const groupFor = (el) => {
    const key = keyOf(el);
    let g = groupsByKey.get(key);
    if (!g) {
      g = { form: formOf(el), container: null, username: null, currentPassword: null,
        newPasswords: [], passwords: [], otp: null, inputs: [], text: '' };
      groupsByKey.set(key, g);
    }
    return g;
  };

  for (const el of all) groupFor(el).inputs.push(el);
  for (const el of ghosts) groupFor(el);
  const loc = (root.ownerDocument || root).defaultView?.location || root.defaultView?.location;
  const path = loc ? `${loc.pathname || ''} ${loc.hash || ''}` : '';
  for (const g of groupsByKey.values()) {
    g.container = g.form || lowestCommonAncestor(g.inputs);
    g.text = groupContextText(g.container);
    g.small = !!g.container && (g.container.textContent || '').length <= 1500 && g.inputs.length <= 6;
    g.ownText = ownTextOf(g.container);
    g.intent = formIntent({ text: g.ownText, submitText: submitTextOf(g.container), path });
  }
  const localCache = new Map();
  const ctxFor = (el) => {
    let t = localCache.get(el);
    if (t === undefined) {
      const g = groupFor(el);
      t = `${g.small ? g.text : ''} ${nearContext(el)}`.trim();
      localCache.set(el, t);
    }
    return t;
  };
  let short2fa = null;
  const shortPage2fa = () => {
    if (short2fa === null) short2fa = looksLikeShort2faPage(pageText(), all.length);
    return short2fa;
  };

  for (const el of ghosts) {
    const g = groupFor(el);
    if (!g.otp) {
      g.otp = { kind: 'single', fields: [el] };
      fields.set(el, { kind: FieldKind.OTP, group: g });
    }
  }

  const splitMembers = new Set();
  for (const run of findSplitOtpGroups(all, ctxFor, { rectOf })) {
    const g = groupFor(run[0]);
    if (!g.otp) {
      g.otp = { kind: 'split', fields: run };
      for (const el of run) { splitMembers.add(el); fields.set(el, { kind: FieldKind.OTP, group: g }); }
    }
  }

  for (const g of groupsByKey.values()) {
    // A card's security code is often type=password.
    const cardForm = looksLikeCardForm(g.inputs);
    const rest = g.inputs.filter((el) => !splitMembers.has(el) && !(cardForm && NOT_LOGIN_CARD_KINDS.has(cardFieldKind(el))));
    const pwEls = [];
    const otpCandidates = [];
    for (const el of rest) {
      const score = otpScore(el, () => ctxFor(el));
      if (score >= 50) otpCandidates.push({ el, score });
      else if (inputType(el) === 'password') pwEls.push(el);
    }
    if (!g.otp && otpCandidates.length) {
      otpCandidates.sort((a, b) => b.score - a.score);
      g.otp = { kind: 'single', fields: [otpCandidates[0].el] };
      fields.set(otpCandidates[0].el, { kind: FieldKind.OTP, group: g });
    }
    if (!g.otp) {
      const el = unnamedOtpField(rest, ctxFor, shortPage2fa);
      if (el) {
        g.otp = { kind: 'single', fields: [el] };
        fields.set(el, { kind: FieldKind.OTP, group: g });
      }
    }

    const kinds = classifyPasswords(pwEls, { intent: g.intent });
    const otpEls = new Set(g.otp ? g.otp.fields : []);
    if (pwEls.length === 1 && kinds[0] === FieldKind.NEW_PASSWORD && loneNewPasswordIsLogin(pwEls[0], rest, g, otpEls, visible)) {
      kinds[0] = FieldKind.CURRENT_PASSWORD;
    }
    pwEls.forEach((el, i) => {
      g.passwords.push({ el, kind: kinds[i] });
      if (kinds[i] === FieldKind.CURRENT_PASSWORD && !g.currentPassword) g.currentPassword = el;
      else if (kinds[i] === FieldKind.NEW_PASSWORD) g.newPasswords.push(el);
      fields.set(el, { kind: kinds[i], group: g });
    });

    const firstPw = pwEls[0];
    let best = null;
    let lastText = null;
    for (const el of rest) {
      if (firstPw && el === firstPw) break;
      if (otpEls.has(el) || inputType(el) === 'password') continue;
      lastText = el;
      const s = usernameScore(el);
      if (s > 0 && (!best || s >= best.score)) best = { el, score: s };
    }
    if (firstPw) {
      if (best && !usernameBacked(best.el, firstPw, g, otpEls, visible)) best = null;
      else if (!best && lastText && anonymousUsername(lastText, pwEls, g, otpEls, visible)) best = { el: lastText, score: 10 };
    }
    // Identifier-first pages: without a password only confident candidates count, so newsletter and
    // search boxes are left alone.
    if (best && !firstPw) {
      const loginish = LOGIN_TEXT_RE.test(normalizeHint(g.text)) || g.intent === 'login' ||
        autocompleteTokens(best.el).some((t) => t === 'username' || t === 'webauthn') ||
        USERNAME_NAME_RE.test(fieldHints(best.el)) ||
        (LOGIN_PATH_RE.test(path) && !NEWSLETTER_RE.test(g.text));
      const fewInputs = rest.length <= 3;
      if (!(best.score >= 100 || (best.score >= 50 && loginish && fewInputs))) best = null;
    }
    if (best) {
      g.username = best.el;
      fields.set(best.el, { kind: FieldKind.USERNAME, group: g });
    }
    g.quiet = isQuietPassword(pwEls, g, otpEls, visible);
  }

  const groups = [...groupsByKey.values()].filter((g) => g.username || g.passwords.length || g.otp);
  return { groups, fields };
}

/** True for an input whose autocomplete asks for passkey autofill (conditional mediation). */
export function isWebauthnField(el) {
  return autocompleteTokens(el).includes('webauthn');
}

// Card and identity fields. Login detection takes precedence: main.js only passes fields that
// detectFields didn't claim.

export const CardField = Object.freeze({
  NAME: 'cc-name', GIVEN_NAME: 'cc-given-name', FAMILY_NAME: 'cc-family-name', NUMBER: 'cc-number',
  EXP: 'cc-exp', EXP_MONTH: 'cc-exp-month', EXP_YEAR: 'cc-exp-year', CSC: 'cc-csc', TYPE: 'cc-type',
});
const CARD_TOKENS = new Set(Object.values(CardField));
const NOT_LOGIN_CARD_KINDS = new Set([CardField.CSC, CardField.EXP, CardField.EXP_MONTH, CardField.EXP_YEAR]);

export const IdentityField = Object.freeze({
  NAME: 'name', HONORIFIC: 'honorific-prefix', GIVEN_NAME: 'given-name', ADDITIONAL_NAME: 'additional-name',
  FAMILY_NAME: 'family-name', ORGANIZATION: 'organization', EMAIL: 'email', TEL: 'tel',
  STREET: 'street-address', LINE1: 'address-line1', LINE2: 'address-line2', LINE3: 'address-line3',
  CITY: 'address-level2', REGION: 'address-level1', POSTAL: 'postal-code', COUNTRY: 'country',
  COUNTRY_NAME: 'country-name',
});
const IDENTITY_TOKENS = new Set([...Object.values(IdentityField), 'tel-national']);
const ADDRESS_KINDS = new Set(['street-address', 'address-line1', 'address-line2', 'address-line3',
  'address-level1', 'address-level2', 'postal-code', 'country', 'country-name']);
const LOGIN_TOKENS = new Set(['username', 'current-password', 'new-password', 'one-time-code', 'webauthn']);

const FORM_INPUT_TYPES = new Set(['', 'text', 'tel', 'number', 'email', 'password', 'month']);

const CC_NEGATIVE_RE = /(gift|loyalty|member|library|reward|bonus|store ?card|kundenkarte|identity ?card|\bid ?card\b|insurance|voucher|coupon|promo|discount|search)/i;
const CC_NAME_RE = /(name ?on ?(the )?card|card ?holder|holder ?name|nameoncard|\bcc ?name\b|card ?name|karteninhaber|titulaire|titular|intestatario|kaarthouder|posiadacz|владелец)/i;
const CC_CSC_RE = /\b(cvv2?|cvc2?|csc|cvn|cid|security ?code|card ?code|card ?verification|verification ?(value|number)|card ?security|prüfnummer|prüfziffer|kartenprüfnummer|cryptogramme|código de seguridad|codice di sicurezza|beveiligingscode)\b/i;
const CC_EXP_RE = /(expir|\bexp\b|\bexpy\b|\bexpm\b|valid ?(thru|through|until)|good ?thru|ablauf|gültig|vencimiento|caducidad|scadenza|vervaldatum|ważności|срок действия|有効期限)/i;
const MONTH_RE = /\b(month|mm|mon|monat|mois|mes|mese|maand|miesiąc|месяц)\b/i;
const YEAR_RE = /\b(year|yy|yyyy|jj|jjjj|aa|aaaa|jahr|année|annee|año|anno|jaar|rok|год)\b/i;
const CC_TYPE_RE = /\b(card ?(type|brand|network)|cc ?type|kartentyp|type de carte|tipo de tarjeta)\b/i;
const CC_NUMBER_RE = /(card ?(number|num|no|nr)\b|\bcc ?(number|num|no)\b|credit ?card|debit ?card|cardnumber|ccnumber|ccnum|kartennummer|numéro de (la )?carte|n° de carte|número de (la )?tarjeta|numero de (la )?tarjeta|numero (della )?carta|kaartnummer|numer karty|номер карты|カード番号|卡号)/i;
// "MM/YY", "MM / YYYY", "MM-JJ", "12/29".
const EXP_PLACEHOLDER_RE = /^\s*(mm|m|\d{2})\s*[/\-. ]?\s*(yyyy|yy|jjjj|jj|aaaa|aa|\d{2}|\d{4})\s*$/i;

const ID_NEGATIVE_RE = /(search|query|captcha|coupon|promo|voucher|discount|message|comment|subject|password|user ?name|\blogin\b|\bcard\b|cvv|cvc|\botp\b|one ?time|verification|ip ?address|\burl\b|website|domain|nick|screen ?name|display ?name|file ?name|quantity|amount|gift)/i;
const EMAIL_RE = /\be ?mail\b|\bemail\b|courriel|correo/i;
const POSTAL_RE = /(\bzip\b|zip ?code|zipcode|postal|post ?code|postcode|\bplz\b|postleitzahl|code postal|código postal|codigo postal|\bcap\b|\bcep\b|postnummer|郵便番号|邮编)/i;
const LINE3_RE = /(address ?(line)? ?3\b|\baddr ?3\b|street ?3\b)/i;
const LINE2_RE = /(address ?(line)? ?2\b|\baddr ?2\b|street ?2\b|apartment|\bapt\b|suite|\bunit\b|building|\bfloor\b|adresszusatz|complément|complemento)/i;
const LINE1_RE = /(address ?(line)? ?1\b|\baddr ?1\b|street|\baddress\b|\baddr\b|straße|strasse|\badresse\b|dirección|direccion|indirizzo|\badres\b|улица|住所|地址)/i;
const CITY_RE = /(\bcity\b|\btown\b|locality|suburb|\bort\b|\bstadt\b|\bville\b|ciudad|città|citta|\bplaats\b|woonplaats|miasto|город|市区町村)/i;
const REGION_RE = /(\bstate\b|province|\bregion\b|county|prefecture|bundesland|département|departement|provincia|regione|\bstaat\b|województwo|область|都道府県)/i;
const COUNTRY_RE = /(country|\bnation\b|\bland\b|\bpays\b|país|\bpaese\b|\bkraj\b|страна)/i;
const ORG_RE = /(company|organi[sz]ation|business ?name|\bfirm\b|employer|\bfirma\b|firmenname|entreprise|société|societe|empresa|azienda|bedrijf)/i;
const GIVEN_RE = /(first ?name|given ?name|fore ?name|\bfname\b|\bfirst\b|vorname|prénom|prenom|voornaam|imię)/i;
const MIDDLE_RE = /(middle ?(name|initial)|\bmiddle\b|\bmname\b)/i;
const FAMILY_RE = /(last ?name|family ?name|sur ?name|\blname\b|\blast\b|nachname|nom de famille|apellidos?|cognome|achternaam|nazwisko|фамилия)/i;
const FULL_NAME_RE = /(\bfull ?name\b|\byour ?name\b|\bname\b|\bnom\b|\bnombre\b|\bnome\b|\bnaam\b|\bимя\b|氏名|姓名)/i;
const TEL_RE = /\b(phone|mobile|cell|handy|telefon|téléphone|teléfono|telefono|телефон|tel|telephone)\b|電話|手机/i;

function isFormControl(el) {
  if (!el || el.disabled) return false;
  if (el.tagName === 'SELECT') return !el.multiple;
  if (el.tagName === 'TEXTAREA') return !el.readOnly;
  if (el.tagName !== 'INPUT' || el.readOnly) return false;
  return FORM_INPUT_TYPES.has(inputType(el));
}

function collectFormControls(root) {
  const out = [];
  const walk = (r) => {
    for (const el of r.querySelectorAll('*')) {
      if (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') out.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(root);
  return out;
}

function tokenIn(el, set) {
  for (const t of autocompleteTokens(el)) if (set.has(t)) return t;
  return null;
}

function selectShape(el) {
  if (el.tagName !== 'SELECT') return null;
  const values = [...el.options].map((o) => (o.value || o.text || '').trim()).filter((v) => /^\d{1,4}$/.test(v)).map(Number);
  if (values.length >= 12 && values.every((v) => v >= 1 && v <= 12)) return 'month';
  const now = new Date().getFullYear();
  if (values.length >= 3 && values.every((v) => (v >= now - 2 && v <= now + 40) || (v >= (now % 100) - 2 && v <= (now % 100) + 40))) return 'year';
  return null;
}

// From the field's own signals only. A "security code" only counts in a form with a card number.
export function cardFieldKind(el) {
  const token = tokenIn(el, CARD_TOKENS);
  if (token) return token;
  const ac = autocompleteTokens(el);
  if (ac.some((t) => LOGIN_TOKENS.has(t) || IDENTITY_TOKENS.has(t))) return null;
  const hints = fieldHints(el);
  if (!hints || CC_NEGATIVE_RE.test(hints)) return null;
  const select = el.tagName === 'SELECT';
  if (el.tagName === 'TEXTAREA') return null;
  if (CC_NAME_RE.test(hints)) return select ? null : CardField.NAME;
  if (CC_CSC_RE.test(hints)) return select ? null : CardField.CSC;
  const placeholder = el.getAttribute('placeholder') || '';
  if (CC_EXP_RE.test(hints) || (!select && EXP_PLACEHOLDER_RE.test(placeholder) && /[a-z]/i.test(placeholder)) || inputType(el) === 'month') {
    const month = MONTH_RE.test(hints);
    const year = YEAR_RE.test(hints);
    if (month && !year) return CardField.EXP_MONTH;
    if (year && !month) return CardField.EXP_YEAR;
    if (select) {
      const shape = selectShape(el);
      return shape === 'month' ? CardField.EXP_MONTH : shape === 'year' ? CardField.EXP_YEAR : null;
    }
    return CardField.EXP;
  }
  if (CC_TYPE_RE.test(hints)) return CardField.TYPE;
  if (CC_NUMBER_RE.test(hints)) return select ? CardField.TYPE : CardField.NUMBER;
  return null;
}

export function identityFieldKind(el) {
  const token = tokenIn(el, IDENTITY_TOKENS);
  if (token) return token === 'tel-national' ? IdentityField.TEL : token;
  const ac = autocompleteTokens(el);
  if (ac.some((t) => LOGIN_TOKENS.has(t) || t.startsWith('cc-'))) return null;
  const type = el.tagName === 'INPUT' ? inputType(el) : '';
  if (type === 'password' || type === 'month') return null;
  const hints = fieldHints(el);
  if (type === 'email') return IdentityField.EMAIL;
  if (!hints || ID_NEGATIVE_RE.test(hints)) return null;
  if (EMAIL_RE.test(hints)) return IdentityField.EMAIL;
  if (POSTAL_RE.test(hints)) return IdentityField.POSTAL;
  if (LINE3_RE.test(hints)) return IdentityField.LINE3;
  if (LINE2_RE.test(hints)) return IdentityField.LINE2;
  if (CITY_RE.test(hints)) return IdentityField.CITY;
  if (REGION_RE.test(hints)) return IdentityField.REGION;
  if (COUNTRY_RE.test(hints)) return el.tagName === 'SELECT' ? IdentityField.COUNTRY : IdentityField.COUNTRY_NAME;
  if (ORG_RE.test(hints)) return IdentityField.ORGANIZATION;
  if (LINE1_RE.test(hints)) return el.tagName === 'TEXTAREA' ? IdentityField.STREET : IdentityField.LINE1;
  if (el.tagName === 'SELECT') return null;
  if (type === 'tel' || TEL_RE.test(hints)) return IdentityField.TEL;
  if (MIDDLE_RE.test(hints)) return IdentityField.ADDITIONAL_NAME;
  if (GIVEN_RE.test(hints)) return IdentityField.GIVEN_NAME;
  if (FAMILY_RE.test(hints)) return IdentityField.FAMILY_NAME;
  if (FULL_NAME_RE.test(hints)) return IdentityField.NAME;
  return null;
}

function isCardGroup(fields) {
  return fields.some(({ el, kind }) => kind === CardField.NUMBER || tokenIn(el, CARD_TOKENS));
}

/**
 * Detects card and identity fields under `root`, grouped per form.
 * @returns {{ cards: CardGroup[], identities: IdentityGroup[], fields: Map<Element, { type: 'card' | 'identity', kind: string, group }> }}
 * Group fields: Map<kind, Element[]>; only cc-number holds several (a split number, in order).
 */
export function detectFormFields(root, opts = {}) {
  return withHintCache(() => detectCardAndIdentityFields(root, opts));
}

function detectCardAndIdentityFields(root, { isVisible: visible = isVisible } = {}) {
  const controls = collectFormControls(root).filter((el) => isFormControl(el) && visible(el));
  const byKey = new Map();
  for (const el of controls) {
    const key = formOf(el) || rootOf(el);
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(el);
  }
  const fields = new Map();
  const cards = [];
  const identities = [];
  for (const els of byKey.values()) {
    const form = formOf(els[0]);
    const container = form || lowestCommonAncestor(els);
    // Cards first: "name on card" is not an identity name.
    const cardFields = [];
    for (const el of els) {
      const kind = cardFieldKind(el);
      if (kind) cardFields.push({ el, kind });
    }
    const cardEls = new Set();
    if (isCardGroup(cardFields)) {
      const group = { type: 'card', form, container, fields: new Map() };
      const add = (kind, el) => {
        if (!group.fields.has(kind)) group.fields.set(kind, []);
        group.fields.get(kind).push(el);
        cardEls.add(el);
        fields.set(el, { type: 'card', kind, group });
      };
      for (const { el, kind } of cardFields) {
        if (kind === CardField.NUMBER || !group.fields.has(kind)) add(kind, el);
      }
      for (const el of els) {
        if (cardEls.has(el)) continue;
        const hints = fieldHints(el);
        const shape = selectShape(el);
        const month = shape === 'month' || (MONTH_RE.test(hints) && !YEAR_RE.test(hints));
        const year = shape === 'year' || (YEAR_RE.test(hints) && !MONTH_RE.test(hints));
        if (month && !group.fields.has(CardField.EXP_MONTH) && !group.fields.has(CardField.EXP)) add(CardField.EXP_MONTH, el);
        else if (year && !group.fields.has(CardField.EXP_YEAR) && !group.fields.has(CardField.EXP)) add(CardField.EXP_YEAR, el);
      }
      // A number split over boxes: only the first is named.
      const number = group.fields.get(CardField.NUMBER);
      if (number?.length === 1 && number[0].tagName === 'INPUT') {
        const ml = maxLength(number[0]);
        if (ml !== null && ml >= 3 && ml <= 6) {
          let prev = number[0];
          for (const el of els.slice(els.indexOf(number[0]) + 1)) {
            if (number.length >= 5 || cardEls.has(el) || el.tagName !== 'INPUT') break;
            const m = maxLength(el);
            if (m === null || m < 3 || m > 7 || !boxesAdjacent(prev, el)) break;
            add(CardField.NUMBER, el);
            prev = el;
          }
        }
      }
      cards.push(group);
    }
    const idFields = [];
    for (const el of els) {
      if (cardEls.has(el)) continue;
      const kind = identityFieldKind(el);
      if (kind) idFields.push({ el, kind });
    }
    const kinds = new Set(idFields.map((f) => f.kind));
    const addressKinds = [...kinds].filter((k) => ADDRESS_KINDS.has(k)).length;
    const explicit = idFields.filter(({ el }) => tokenIn(el, IDENTITY_TOKENS)).length;
    // A whole contact or address form, not a lone e-mail box.
    if (addressKinds >= 2 || kinds.size >= 3 || (explicit >= 2 && kinds.size >= 2)) {
      const group = { type: 'identity', form, container, fields: new Map() };
      for (const { el, kind } of idFields) {
        if (group.fields.has(kind)) continue; // billing before shipping copies
        group.fields.set(kind, [el]);
        fields.set(el, { type: 'identity', kind, group });
      }
      identities.push(group);
    }
  }
  return { cards, identities, fields };
}

function looksLikeCardForm(els) {
  return isCardGroup(els.map((el) => ({ el, kind: cardFieldKind(el) })).filter((f) => f.kind));
}
