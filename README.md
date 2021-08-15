## BEHAVIOR_BASED_DETECTION
### Injector
- explorer.exe에 globalhook.dll과 myhook.dll을 Injection, Ejection을 해주는 도구

```
사용법

Injection.exe -i explorer.exe globalhook.dll myhook.dll
```

### globalhook
- global hooking을 위해 만든 dll 
- 절대 경로를 적어두지 않아 위해서 System32 디렉토리에 넣어준다.
- CreateProcessA와 CreateProcessW를 Hooking 하여 자식 프로세스도 globalhook, myhook이 자동으로 Injection을 하도록 해준다.

### myhook
- 사용자가 정의한 API Hooking API
- 절대 경로를 적어두지 않아 위해서 System32 디렉토리에 넣어준다.
- 현재 CreateFileW, CreateFileA를 Hooking 하여, System32 폴더에 파일을 생성하거나, 그 외에 폴더에 sys 파일을 생성할 경우, 알림을 주고, 차단 여부를 결정하게 한다.

### detector
- Hooking 시 발생하는 OutputDebugStringA의 메시지를 활용하여, 여러 API 조합으로 이루어진 악성코드 API 패턴과 일치하는지 비교하여 해당 프로세스가 악성프로세스라고 판단하면, 알림을 통해 차단 여부를 사용자가 결정하게 한다.



