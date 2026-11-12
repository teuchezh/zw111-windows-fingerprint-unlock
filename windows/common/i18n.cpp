#include "i18n.h"

namespace zw {

#define ZW_RU(id, ru, en) ru,
#define ZW_EN(id, ru, en) en,
static const wchar_t* const kRu[] = { ZW_STRINGS(ZW_RU) };
static const wchar_t* const kEn[] = { ZW_STRINGS(ZW_EN) };
#undef ZW_RU
#undef ZW_EN

static Lang DetectLang() {
    LANGID id = GetUserDefaultUILanguage();
    if (PRIMARYLANGID(id) == LANG_NEUTRAL) id = GetSystemDefaultUILanguage();
    return PRIMARYLANGID(id) == LANG_RUSSIAN ? Lang::Ru : Lang::En;
}

static Lang g_lang = DetectLang();

Lang CurrentLang() { return g_lang; }
void SetLang(Lang l) { g_lang = l; }
void SetLangFromSetting(const std::wstring& s) {
    if (_wcsicmp(s.c_str(), L"ru") == 0) g_lang = Lang::Ru;
    else if (_wcsicmp(s.c_str(), L"en") == 0) g_lang = Lang::En;
    else g_lang = DetectLang();
}

const wchar_t* T(S id) {
    size_t i = (size_t)id;
    if (i >= (size_t)S::COUNT) return L"";
    return g_lang == Lang::Ru ? kRu[i] : kEn[i];
}

} // namespace zw
