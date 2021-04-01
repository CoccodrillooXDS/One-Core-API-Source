@ stdcall AcquireSRWLockExclusive(ptr) kernelbase.AcquireSRWLockExclusive
@ stdcall AcquireSRWLockShared(ptr) kernelbase.AcquireSRWLockShared
@ stdcall CancelWaitableTimer(long) kernelbase.CancelWaitableTimer
@ stdcall CreateEventA(ptr long long str) kernelbase.CreateEventA
@ stdcall CreateEventExA(ptr str long long) kernelbase.CreateEventExA
@ stdcall CreateEventExW(ptr wstr long long) kernelbase.CreateEventExW
@ stdcall CreateEventW(ptr long long wstr) kernelbase.CreateEventW
@ stdcall CreateMutexA(ptr long str) kernelbase.CreateMutexA
@ stdcall CreateMutexExA(ptr str long long) kernelbase.CreateMutexExA
@ stdcall CreateMutexExW(ptr wstr long long) kernelbase.CreateMutexExW
@ stdcall CreateMutexW(ptr long wstr) kernelbase.CreateMutexW
@ stdcall CreateSemaphoreExW(ptr long long wstr long long) kernelbase.CreateSemaphoreExW
@ stdcall CreateWaitableTimerExW(ptr wstr long long) kernelbase.CreateWaitableTimerExW
@ stdcall DeleteCriticalSection(ptr) kernelbase.DeleteCriticalSection
@ stdcall DeleteSynchronizationBarrier(ptr) kernelbase.DeleteSynchronizationBarrier
@ stdcall EnterCriticalSection(ptr) kernelbase.EnterCriticalSection
@ stdcall EnterSynchronizationBarrier(ptr long) kernelbase.EnterSynchronizationBarrier
@ stdcall InitOnceBeginInitialize(ptr long ptr ptr) kernelbase.InitOnceBeginInitialize
@ stdcall InitOnceComplete(ptr long ptr) kernelbase.InitOnceComplete
@ stdcall InitOnceExecuteOnce(ptr ptr ptr ptr) kernelbase.InitOnceExecuteOnce
@ stdcall InitOnceInitialize(ptr) kernelbase.InitOnceInitialize
@ stdcall InitializeConditionVariable(ptr) kernelbase.InitializeConditionVariable
@ stdcall InitializeCriticalSection(ptr) kernelbase.InitializeCriticalSection
@ stdcall InitializeCriticalSectionAndSpinCount(ptr long) kernelbase.InitializeCriticalSectionAndSpinCount
@ stdcall InitializeCriticalSectionEx(ptr long long) kernelbase.InitializeCriticalSectionEx
@ stdcall InitializeSRWLock(ptr) kernelbase.InitializeSRWLock
@ stdcall InitializeSynchronizationBarrier(ptr long long) kernelbase.InitializeSynchronizationBarrier
@ stdcall LeaveCriticalSection(ptr) kernelbase.LeaveCriticalSection
@ stdcall OpenEventA(long long str) kernelbase.OpenEventA
@ stdcall OpenEventW(long long wstr) kernelbase.OpenEventW
@ stdcall OpenMutexW(long long wstr) kernelbase.OpenMutexW
@ stdcall OpenSemaphoreW(long long wstr) kernelbase.OpenSemaphoreW
@ stdcall OpenWaitableTimerW(long long wstr) kernelbase.OpenWaitableTimerW
@ stdcall ReleaseMutex(long) kernelbase.ReleaseMutex
@ stdcall ReleaseSRWLockExclusive(ptr) kernelbase.ReleaseSRWLockExclusive
@ stdcall ReleaseSRWLockShared(ptr) kernelbase.ReleaseSRWLockShared
@ stdcall ReleaseSemaphore(long long ptr) kernelbase.ReleaseSemaphore
@ stdcall ResetEvent(long) kernelbase.ResetEvent
@ stdcall SetCriticalSectionSpinCount(ptr long) kernelbase.SetCriticalSectionSpinCount
@ stdcall SetEvent(long) kernelbase.SetEvent
@ stdcall SetWaitableTimer(long ptr long ptr ptr long) kernelbase.SetWaitableTimer
@ stdcall SetWaitableTimerEx(long ptr long ptr ptr ptr long) kernelbase.SetWaitableTimerEx
@ stdcall SignalObjectAndWait(long long long long) kernelbase.SignalObjectAndWait
@ stdcall Sleep(long) kernelbase.Sleep
@ stdcall SleepConditionVariableCS(ptr ptr long) kernelbase.SleepConditionVariableCS
@ stdcall SleepConditionVariableSRW(ptr ptr long long) kernelbase.SleepConditionVariableSRW
@ stdcall SleepEx(long long) kernelbase.SleepEx
@ stdcall TryAcquireSRWLockExclusive(ptr) kernelbase.TryAcquireSRWLockExclusive
@ stdcall TryAcquireSRWLockShared(ptr) kernelbase.TryAcquireSRWLockShared
@ stdcall TryEnterCriticalSection(ptr) kernelbase.TryEnterCriticalSection
@ stdcall WaitForMultipleObjectsEx(long ptr long long long) kernelbase.WaitForMultipleObjectsEx
@ stdcall WaitForSingleObject(long long) kernelbase.WaitForSingleObject
@ stdcall WaitForSingleObjectEx(long long long) kernelbase.WaitForSingleObjectEx
@ stub WaitOnAddress
@ stdcall WakeAllConditionVariable(ptr) kernelbase.WakeAllConditionVariable
@ stub WakeByAddressAll
@ stub WakeByAddressSingle
@ stdcall WakeConditionVariable(ptr) kernelbase.WakeConditionVariable
