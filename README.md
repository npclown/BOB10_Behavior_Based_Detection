## BEHAVIOR_BASED_DETECTION

### Injector
- Æ¯Á¤ ÇÁ·Î¼¼¼­¿¡ dllÀ» Injection, Ejection ½ÃÄÑÁÖ´Â µµ±¸

```
Injection.exe -i <process ¸í> <dll ¸í>
```

### detector
- Hooking ÇÑ API¸¦ »ç¿ë½Ã ¹ß»ıÇÏ´Â debug log¸¦ ¹Ş¾Æ¼­, Æ¯Á¤ ÇÁ·Î¼¼½º°¡ ½Ã³ª¸®¿À¸¦ ¸¸Á·ÇÏ´ÂÁö ºñ±³ÇÏ¿©, ¾Ç¼º Å°·Î°Å¶ó°í ÆÇ´ÜµÇ¸é ¾Ë¸²À» ÅëÇØ Â÷´Ü ¿©ºÎ¸¦ »ç¿ëÀÚ¿¡°Ô ¾Ë·ÁÁÖ´Â ÇÁ·Î±×·¥

### globalhook
- global hookingÀ» ¼öÇàÇÏ´Â dll
- CreateProcessA,€ CreateProcessW¸¦ ÈÄÅ·ÇÏ¿©, ÀÚ½Ä ÇÁ·Î¼¼½º¿¡ globalhook.dll ¿Í myhook.dll ÀÌ ÀÚµ¿À¸·Î InjectionÀ» ½ÃÄÑÁÖµµ·Ï ÇÑ´Ù.

### myhook
- ÇàÀ§±â¹İ Å½Áö¿¡ ÇÊ¿äÇÑ API¸¦ ÈÄÅ·ÇÏ´Â dll

### Implementation of Scenario Algorithm
- ¾Ç¼ºÄÚµå ½Ã³ª¸®¿À¸¦ »ı¼ºÇÒ ¶§ »ç¿ë

## Requirements
- Windows7 32bit
- Visual studio 2019

## »ç¿ë¹ı
- Clone from Github
```
git clone https://github.com/NPclown/BOB10_Behavior_Based_Detection.git
cd BOB10_Behavior_Based_Detection
cd src

Build.sln ½ÇÇà
```

- Build ¼öÇà
```
x86À¸·Î ºôµå¸¦ ¼öÇà
```

- dll ÆÄÀÏ ÀÌµ¿
```
BOB10_Behavior_Based_Detection\Build\Debugx86
BOB10_Behavior_Based_Detection\Build\Releasex86 

ÇÏÀ§¿¡ »ı¼ºµÇ´Â globalhook.dll °ú myhook.dllÀ» C:\Windows\System32 ·Î ÀÌµ¿
```

- Detector ½ÇÇà

- Injector ½ÇÇà
```
# ÀÎÁ§¼ÇÀ» ¼öÇàÇÒ ¶§
Injector.exe -i explorer.exe globalhook.dll

# ÀÌÁ§¼ÇÀ» ¼öÇàÇÒ ¶§
Injector.exe -e explorer.exe globalhook.dll
```



