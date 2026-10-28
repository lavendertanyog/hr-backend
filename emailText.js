// Wording of the emails the system sends, per language. A person's language is saved on their
// account (users.preferred_language); anything not in this list falls back to English.
// The Mandarin text has been drafted, not reviewed: have a native speaker check it before launch.

const LANGUAGES = ['en', 'zh'];

function normalizeLanguage(value) {
  const v = String(value || '').trim().toLowerCase();
  return v.startsWith('zh') ? 'zh' : 'en';
}

const TEXT = {
  en: {
    verification: {
      subject: 'Verify your Nextan Portal email',
      heading: 'Verify your email',
      body: (email) => `Confirm this is your email address (${email}) to finish setting up your account - this link expires in 24 hours.`,
      button: 'Verify email',
      footer: "If you didn't create an account, you can safely ignore this email.",
    },
    tempPassword: {
      subject: 'Your temporary Nextan Portal password',
      heading: 'Your temporary password',
      body: 'We received a request to reset the password for your Nextan Portal account. Use the temporary password below to log in, then set a new password from your Profile page.',
      footer: "If you didn't request a password reset, please let your HR admin know - your password has already been changed to the one above.",
    },
    clockIn: {
      subject: "You haven't clocked in yet",
      heading: 'Time to clock in',
      body: "Hi, it's past 8:30am and you haven't clocked in today. Head to the Staff Portal to clock in.",
      button: 'Clock in now',
      footer: 'Already clocked in? You can ignore this.',
    },
    weeklyReport: {
      subject: 'Your weekly report is waiting',
      heading: 'Your weekly report is due',
      body: (which) => (which === 'monday'
        ? "Hi, your weekly report for last week is still missing. It was due on Friday. Please add it this morning."
        : "Hi, your weekly report for this week hasn't been submitted yet. It was due on Friday. It only takes a few minutes."),
      button: 'Write my report',
      footer: 'Already submitted? You can ignore this.',
    },
    accountActive: {
      subject: 'Your Nextan Portal account is active',
      heading: 'Your Nextan Portal account is active',
      body: 'Your account has been approved. You can now log in with the email and password you signed up with.',
      button: 'Log in',
      footer: "You're receiving this because an account was requested with this email address.",
    },
  },
  zh: {
    verification: {
      subject: '验证您的 Nextan 门户邮箱',
      heading: '验证您的邮箱',
      body: (email) => `请确认这是您的邮箱地址（${email}），以完成账户设置。此链接将在 24 小时后失效。`,
      button: '验证邮箱',
      footer: '如果您没有创建账户，请忽略此邮件。',
    },
    tempPassword: {
      subject: '您的 Nextan 门户临时密码',
      heading: '您的临时密码',
      body: '我们收到了重置您 Nextan 门户账户密码的请求。请使用下方的临时密码登录，然后在“个人资料”页面设置新密码。',
      footer: '如果您没有申请重置密码，请告知您的 HR 管理员。您的密码已被更改为上方的密码。',
    },
    clockIn: {
      subject: '您今天还没有打卡',
      heading: '该打卡了',
      body: '您好，现在已过上午 8:30，您今天还没有打卡。请前往员工门户打卡。',
      button: '立即打卡',
      footer: '已经打卡了？请忽略此邮件。',
    },
    weeklyReport: {
      subject: '您的周报还没有提交',
      heading: '该提交周报了',
      body: (which) => (which === 'monday'
        ? '您好，您上周的周报还没有提交，截止时间是周五。请今天上午补交。'
        : '您好，您本周的周报还没有提交，截止时间是周五。只需要几分钟。'),
      button: '填写周报',
      footer: '已经提交了？请忽略此邮件。',
    },
    accountActive: {
      subject: '您的 Nextan 门户账户已激活',
      heading: '您的 Nextan 门户账户已激活',
      body: '您的账户已获批准。您现在可以使用注册时的邮箱和密码登录。',
      button: '登录',
      footer: '您收到此邮件是因为有人使用此邮箱地址申请了账户。',
    },
  },
};

function emailText(lang) {
  return TEXT[normalizeLanguage(lang)] || TEXT.en;
}

module.exports = { emailText, normalizeLanguage, LANGUAGES };
