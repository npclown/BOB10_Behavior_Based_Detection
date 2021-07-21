#_*_ coding:utf-8 _*_

"""
BoB 10th 보안제품개발 트랙 이준성

CopyRight all served by Lee.JoonSung

Object : main source code 윈도우 서비스 등록
"""


# Import major Libs...ㅔ
import servicemanager
import os, sys,time, string
import win32event
import win32service
import win32serviceutil
import subprocess


"""
Usage :
            서비스 설치 :       파일명.exe --startup=suto install
            서비스 삭제 :       파일명.exe remove
"""


# 윈도우 TaskService 등록 class 선언 및 정의
class BBD_Service(win32serviceutil.ServiceFramework):
    _svc_name_ = "BoB_Heuristic_Engine" # 등록될 서비스명 정의
    _svc_display_name_ = "BoB_Heuristic_Engine" # 사용자에게 보여질 서비스명 정의
    _svc_description_ = "BoB 10기 김종민 멘토님 레포!! - aka 화이팅~" # 서비스 설명 정의


    # self __init__ 함수
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False # svc_starter에서 서비스 지속을 위한 지표로 사용

    # 서비스 종료 시
    def svc_stopper(self): # 서비스 '사용 안함' 설정 할 시에, 프로세스 강제 종료
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        subprocess.Popen("taskkill /im BDD_1.exe /f", shell=True) # 프로세스 강제 종료
        win32event.SetEvent(self.hWaitStop)

        self.is_running = False # 종료하면 is_running value False로 설정
        self.timeout = 120000  # 2분

    # 서비스 시작 시..
    def svc_starter(self):
        self.is_running = FutureWarning
        # 파일이 위치한 현재 경로를 확인함
        current_location = str(os.path.abspath(os.path.dirname(sys.argv[0])))
        while self.is_running: # 이 부분이 서비스에 등록 시키는 부분
            rc = win32event.WaitForSingleObject(self.hWaitStop, self.timeout)
            if rc == win32event.WAIT_OBJECT_0:
                break
            else:
                try:
                    subprocess.Popen([current_location+"\\BBD_1.exe"])
                except:
                    pass # 이거 안하면 unhandled exception 에러 자꾸 뜸;;
        time.sleep(60)


"""
def ctrlHandler(ctrlType):
    # 이 부분은 win32api 에서 setConsoleCtrlHandler 사용할 때 쓰려 했는데,
    # win32api가 생각보다 상태가 안좋음...
    return True
"""

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # 이부분 라이브러리 오류 자꾸 나는데, 작동에는 큰 상관 없는듯.... 파이참 문제인듯
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BBD_Service)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(BBD_Service)




