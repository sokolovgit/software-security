#!/usr/bin/env bash
# Регресійний набір для варіанта 19 (профіль автентифікації).
# Кожен тест кодує безпекову ВЛАСТИВІСТЬ, яка має виконуватись.
# На вразливому коді тест падає (FAIL), на виправленому — проходить (PASS).
# Використання: TARGET=http://127.0.0.1:3001 bash tests/regression.sh
set -u
T="${TARGET:-http://127.0.0.1:3000}"
ADMIN="admin@juice-sh.op"; PASS_OK="admin123"
pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
jtok(){ python3 -c "import json,sys;d=json.load(sys.stdin);print((d.get('authentication') or {}).get('token',''))" 2>/dev/null; }

echo "Регресійні тести автентифікації проти $T"

# R1 (V1,CWE-89): ін'єкція в полі email НЕ повинна автентифікувати.
r=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data '{"email":"'"'"' OR 1=1--","password":"x"}')
[ -z "$(echo "$r" | jtok)" ] && ok "R1 SQLi login bypass заблоковано (CWE-89)" || no "R1 SQLi повертає токен (CWE-89)"

# R2 (V2,CWE-321/347): токен, підписаний відомим жорстко закодованим ключем 1024-біт, НЕ приймається.
F=$(cd exploits && .venv/bin/python forge_jwt.py 2>/dev/null | tail -1)
code=$(curl -s -o /dev/null -w '%{http_code}' --cookie "token=$F" "$T/rest/user/whoami")
who=$(curl -s --cookie "token=$F" "$T/rest/user/whoami" | python3 -c "import json,sys;print((json.load(sys.stdin).get('user') or {}).get('email') or 'none')" 2>/dev/null)
[ "$who" = "attacker@evil.test" ] && no "R2 підроблений JWT прийнято ($who) (CWE-321)" || ok "R2 підроблений JWT відхилено (CWE-321)"

# R3 (V3,CWE-916): хеш пароля у БД НЕ має бути простим MD5 (перевірка через витік хешу з V1 неможлива після фіксу R1,
#   тому перевіряємо напряму: md5(відомий пароль) не збігається зі збереженим хешем).
# Отримуємо хеш через легітимний вхід адміна і порівнюємо з md5.
login=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"$PASS_OK\"}")
tok=$(echo "$login" | jtok)
if [ -n "$tok" ]; then
  stored=$(echo "$tok" | cut -d. -f2 | python3 -c "import sys,base64,json;s=sys.stdin.read().strip();s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s))['data'].get('password',''))" 2>/dev/null)
  md5=$(python3 -c "import hashlib;print(hashlib.md5(b'$PASS_OK').hexdigest())")
  if [ -n "$stored" ] && [ "$stored" = "$md5" ]; then no "R3 пароль зберігається як незасолений MD5 (CWE-916)"; else ok "R3 пароль не є незасоленим MD5 (CWE-916)"; fi
else
  no "R3 не вдалося увійти легітимно для перевірки"
fi

# R5 (V5,CWE-620): зміна пароля БЕЗ поточного пароля має відхилятись.
tok=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"$PASS_OK\"}" | jtok)
code=$(curl -s -G "$T/rest/user/change-password" -H "Authorization: Bearer=$tok" --data-urlencode "new=hacked1" --data-urlencode "repeat=hacked1" -o /dev/null -w '%{http_code}')
if [ "$code" = "401" ] || [ "$code" = "403" ]; then ok "R5 зміна пароля без current відхилена (HTTP $code) (CWE-620)"
else
  # перевіряємо чи реально змінився
  chk=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"hacked1\"}" -o /dev/null -w '%{http_code}')
  if [ "$chk" = "200" ]; then no "R5 пароль змінено без знання поточного (CWE-620)"
    # відновлення: входимо з новим паролем (свіжий in-memory запис), потім міняємо назад із current
    rtok=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"hacked1\"}" | jtok)
    curl -s -G "$T/rest/user/change-password" -H "Authorization: Bearer=$rtok" --data-urlencode "current=hacked1" --data-urlencode "new=$PASS_OK" --data-urlencode "repeat=$PASS_OK" -o /dev/null
  else ok "R5 зміна пароля без current не призвела до зміни (HTTP $code) (CWE-620)"; fi
fi

# R6 (V6,CWE-613): після виходу токен має відкликатись (logout інвалідовує серверну сесію).
tok=$(curl -s -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"$PASS_OK\"}" | jtok)
before=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" "$T/rest/user/authentication-details")
curl -s -o /dev/null -X POST -H "Authorization: Bearer $tok" "$T/rest/user/logout" 2>/dev/null
after=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" "$T/rest/user/authentication-details")
if [ "$before" = "200" ] && [ "$after" = "401" ]; then ok "R6 токен відкликано після виходу ($before -> $after) (CWE-613)"
else no "R6 токен чинний після виходу ($before -> $after) (CWE-613)"; fi

# R4 (V4,CWE-307): брутфорс логіну має обмежуватись (після N спроб — 429).
codes=""; for i in $(seq 1 25); do c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$T/rest/user/login" -H 'Content-Type: application/json' --data "{\"email\":\"$ADMIN\",\"password\":\"zzz$i\"}"); codes="$codes $c"; done
n429=$(echo $codes | tr ' ' '\n' | grep -c 429)
[ "$n429" -gt 0 ] && ok "R4 обмеження частоти спрацювало ($n429/25 -> 429) (CWE-307)" || no "R4 немає обмеження частоти (0/25 -> 429) (CWE-307)"
sleep 1
sleep 1

echo "ПІДСУМОК: PASS=$pass FAIL=$fail"
exit $fail
