<?php
declare(strict_types=1);

/** Język interfejsu (pl/en) i wypełnianie szablonów pages/*.html kluczami {{...}}. */
final class Lang
{
    public const COOKIE = 'bl_lang';
    public const SUPPORTED = ['pl', 'en'];

    /** Ciasteczko z przełącznika wygrywa, potem najwyżej oceniony obsługiwany język z Accept-Language, domyślnie angielski. */
    public static function pick(?string $cookie, string $acceptLanguage): string
    {
        if (in_array($cookie, self::SUPPORTED, true)) {
            return $cookie;
        }
        $best = 'en';
        $bestQ = 0.0;
        foreach (explode(',', $acceptLanguage) as $part) {
            if (!preg_match('/^\s*([a-zA-Z]{1,8})(?:-[a-zA-Z0-9]{1,8})*\s*(?:;\s*q=([01](?:\.\d{0,3})?))?\s*$/', $part, $m)) {
                continue;
            }
            $code = strtolower($m[1]);
            $q = isset($m[2]) ? (float) $m[2] : 1.0;
            if (in_array($code, self::SUPPORTED, true) && $q > $bestQ) {
                [$best, $bestQ] = [$code, $q];
            }
        }
        return $best;
    }

    public static function render(string $template, string $lang, string $dir): string
    {
        $strings = require $dir . '/' . $lang . '.php';
        $map = ['{{lang}}' => $lang];
        $js = [];
        foreach ($strings as $key => $value) {
            if (str_starts_with($key, 'js_')) {
                $js[substr($key, 3)] = $value;
            } else {
                $map['{{' . $key . '}}'] = htmlspecialchars($value, ENT_QUOTES);
            }
        }
        $map['{{js}}'] = htmlspecialchars(json_encode($js, JSON_UNESCAPED_UNICODE), ENT_QUOTES);
        return strtr($template, $map);
    }
}
