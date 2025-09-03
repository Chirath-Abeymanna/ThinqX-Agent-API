
# API Configuration - SET YOUR KEYS HERE
VIRUSTOTAL_API_KEY = "409076748abffb92e8cce95805ec187b1f620fecae95e60feb0d1b80ec3ed42e"

# CMS-specific configuration
CMS_FINGERPRINTS = {
    'WordPress': {
        'patterns': ['wp-content', 'wp-includes', '/wp-admin/', '/wp-json/'],
        'generator_tag': r'<meta name="generator" content="WordPress.*?"',
        'version_files': ['readme.html', 'wp-includes/version.php'],
        'admin_path': '/wp-admin/',
        'login_path': '/wp-login.php'
    },
    'Joomla': {
        'patterns': ['joomla', 'option=com_', '/administrator/'],
        'generator_tag': r'<meta name="generator" content="Joomla.*?"',
        'version_files': ['README.txt', 'administrator/manifests/files/joomla.xml'],
        'admin_path': '/administrator/',
        'login_path': '/administrator/index.php'
    },
    'Drupal': {
        'patterns': ['drupal', 'sites/default', '/core/'],
        'generator_tag': r'<meta name="generator" content="Drupal.*?"',
        'version_files': ['CHANGELOG.txt', 'core/CHANGELOG.txt'],
        'admin_path': '/admin/',
        'login_path': '/user/login'
    },
    'Wix': {
        'patterns': [
            'wix.com', 
            '_wixCss', 
            '_wixJs',
            'wix-dropdown-menu',
            'wixui',
            'wixcode-',
            'wix-script',
            'wix-elements',
            'wix-viewer',
            'static.wixstatic.com'
        ],
        'generator_tag': r'<meta name="generator" content="Wix\.com.*?"',
        'version_files': [],  # Wix is SaaS, no direct version files
        'admin_path': 'https://www.wix.com/my-account/site-selector/',
        'login_path': 'https://users.wix.com/signin'
    },
    
    'Shopify': {
        'patterns': [
            'shopify.com',
            '/cdn.shopify.com/',
            'Shopify.theme',
            'shopify-section',
            'shopify-payment-button',
            'shopify-buy',
            'shop.app',
            'shopifycdn.com',
            'myshopify.com',
            'Shopify.shop'
        ],
        'generator_tag': r'<meta name="generator" content="Shopify.*?"',
        'version_files': [],  # Shopify is SaaS, no direct version files
        'admin_path': '/admin',
        'login_path': '/admin/auth/login'
    },
    
    'Squarespace': {
        'patterns': [
            'squarespace.com',
            'squarespace-cdn.com',
            'sqsp.com',
            'squarespace.config',
            'squarespace-script'
        ],
        'generator_tag': r'<meta name="generator" content="Squarespace.*?"',
        'version_files': [],
        'admin_path': '/config',
        'login_path': '/account/login'
    }
}

# Common CMS paths for directory brute-forcing
CMS_DIRECTORY_WORDLIST = [
    'wp-admin', 'wp-includes', 'wp-content', 'administrator', 'admin', 'user',
    'login', 'wp-login.php', 'xmlrpc.php', 'readme.html', 'CHANGELOG.txt',
    'configuration.php', 'wp-config.php', 'config.php', '.env', 'settings.php',
    'wp-content/plugins', 'wp-content/themes', 'sites/default', 'core'
]

# OWASP Top 10 vulnerability patterns
OWASP_PATTERNS = {
    'SQL Injection': r'\berror.*(mysql|sql|database)\b',
    'XSS': r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
    'File Inclusion': r'\b(include|require)(_once)?\s*\(?\s*[\'"].*?[\'"]\s*\)?',
    'Insecure Direct Object References': r'\bid=\d+\b|\bfile=[\w-]+\b'
}

# User enumeration patterns
USER_ENUMERATION_PATHS = [
    '/wp-json/wp/v2/users', '/?author=1', '/user/1', '/api/users'
]

