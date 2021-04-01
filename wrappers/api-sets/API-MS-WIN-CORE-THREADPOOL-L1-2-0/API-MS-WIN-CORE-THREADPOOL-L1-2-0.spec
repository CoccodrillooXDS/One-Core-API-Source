@ stdcall CallbackMayRunLong(ptr) kernelbase.CallbackMayRunLong
@ stdcall CancelThreadpoolIo(ptr) kernelbase.CancelThreadpoolIo
@ stdcall CloseThreadpool(ptr) kernelbase.CloseThreadpool
@ stdcall CloseThreadpoolCleanupGroup(ptr) kernelbase.CloseThreadpoolCleanupGroup
@ stdcall CloseThreadpoolCleanupGroupMembers(ptr long ptr) kernelbase.CloseThreadpoolCleanupGroupMembers
@ stdcall CloseThreadpoolIo(ptr) kernelbase.CloseThreadpoolIo
@ stdcall CloseThreadpoolTimer(ptr) kernelbase.CloseThreadpoolTimer
@ stdcall CloseThreadpoolWait(ptr) kernelbase.CloseThreadpoolWait
@ stdcall CloseThreadpoolWork(ptr) kernelbase.CloseThreadpoolWork
@ stdcall CreateThreadpool(ptr) kernelbase.CreateThreadpool
@ stdcall CreateThreadpoolCleanupGroup() kernelbase.CreateThreadpoolCleanupGroup
@ stdcall CreateThreadpoolIo(ptr) kernelbase.CreateThreadpoolIo
@ stdcall CreateThreadpoolTimer(ptr ptr ptr) kernelbase.CreateThreadpoolTimer
@ stdcall CreateThreadpoolWait(ptr ptr ptr) kernelbase.CreateThreadpoolWait
@ stdcall CreateThreadpoolWork(ptr ptr ptr) kernelbase.CreateThreadpoolWork
@ stdcall DisassociateCurrentThreadFromCallback(ptr) kernelbase.DisassociateCurrentThreadFromCallback
@ stdcall FreeLibraryWhenCallbackReturns(ptr ptr) kernelbase.FreeLibraryWhenCallbackReturns
@ stdcall IsThreadpoolTimerSet(ptr) kernelbase.IsThreadpoolTimerSet
@ stdcall LeaveCriticalSectionWhenCallbackReturns(ptr ptr) kernelbase.LeaveCriticalSectionWhenCallbackReturns
@ stdcall QueryThreadpoolStackInformation(ptr ptr) kernelbase.QueryThreadpoolStackInformation
@ stdcall ReleaseMutexWhenCallbackReturns(ptr long) kernelbase.ReleaseMutexWhenCallbackReturns
@ stdcall ReleaseSemaphoreWhenCallbackReturns(ptr long long) kernelbase.ReleaseSemaphoreWhenCallbackReturns
@ stdcall SetEventWhenCallbackReturns(ptr long) kernelbase.SetEventWhenCallbackReturns
@ stdcall SetThreadpoolStackInformation(ptr ptr) kernelbase.SetThreadpoolStackInformation
@ stdcall SetThreadpoolThreadMaximum(ptr long) kernelbase.SetThreadpoolThreadMaximum
@ stdcall SetThreadpoolThreadMinimum(ptr long) kernelbase.SetThreadpoolThreadMinimum
@ stdcall SetThreadpoolTimer(ptr ptr long long) kernelbase.SetThreadpoolTimer
@ stdcall SetThreadpoolTimerEx(ptr ptr long long) kernelbase.SetThreadpoolTimerEx
@ stdcall SetThreadpoolWait(ptr long ptr) kernelbase.SetThreadpoolWait
@ stdcall SetThreadpoolWaitEx(ptr ptr ptr) kernelbase.SetThreadpoolWaitEx
@ stdcall StartThreadpoolIo(ptr) kernelbase.StartThreadpoolIo
@ stdcall SubmitThreadpoolWork(ptr) kernelbase.SubmitThreadpoolWork
@ stdcall TrySubmitThreadpoolCallback(ptr ptr ptr) kernelbase.TrySubmitThreadpoolCallback
@ stdcall WaitForThreadpoolIoCallbacks(ptr long) kernelbase.WaitForThreadpoolIoCallbacks
@ stdcall WaitForThreadpoolTimerCallbacks(ptr long) kernelbase.WaitForThreadpoolTimerCallbacks
@ stdcall WaitForThreadpoolWaitCallbacks(ptr long) kernelbase.WaitForThreadpoolWaitCallbacks
@ stdcall WaitForThreadpoolWorkCallbacks(ptr long) kernelbase.WaitForThreadpoolWorkCallbacks
