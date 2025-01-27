from languages import LANGUAGES
import json
import os

class LanguageManager:
    def __init__(self):
        self.current_language = 'zh_CN'  # 默认语言
        self.languages = LANGUAGES
        self.load_language_preference()

    def load_language_preference(self):
        """从配置文件加载语言偏好"""
        try:
            if os.path.exists('language_preference.json'):
                with open('language_preference.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.current_language = data.get('language', 'zh_CN')
        except Exception:
            self.current_language = 'zh_CN'

    def save_language_preference(self):
        """保存语言偏好到配置文件"""
        try:
            with open('language_preference.json', 'w', encoding='utf-8') as f:
                json.dump({'language': self.current_language}, f)
        except Exception:
            pass

    def set_language(self, language_code):
        """设置当前语言"""
        if language_code in self.languages:
            self.current_language = language_code
            self.save_language_preference()
            return True
        return False

    def get_text(self, key):
        """获取指定键的文本"""
        try:
            return self.languages[self.current_language].get(key, key)
        except KeyError:
            return key

    def get_available_languages(self):
        """获取可用的语言列表"""
        return list(self.languages.keys()) 