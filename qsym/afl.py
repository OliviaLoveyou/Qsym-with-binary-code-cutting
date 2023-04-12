import atexit
import copy
import logging
import functools
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import time

import pyinotify

from conf import SO
import executor
import minimizer
import utils
#******************
import struct

DEFAULT_TIMEOUT = 90
MAX_TIMEOUT = 10 * 60 # 10 minutes
TARGET_FILE = utils.AT_FILE

MAX_ERROR_REPORTS = 30
MAX_CRASH_REPORTS = 30

# minimum number of hang files to increase timeout
MIN_HANG_FILES = 30

logger = logging.getLogger('qsym.afl')

def get_score(testcase):
    # New coverage is the best
    score1 = testcase.endswith("+cov")
    # NOTE: seed files are not marked with "+cov"
    # even though it contains new coverage
    score2 = "orig:" in testcase
    # Smaller size is better
    score3 = -os.path.getsize(testcase)
    # Since name contains id, so later generated one will be chosen earlier
    score4 = testcase
    return (score1, score2, score3, score4)

def testcase_compare(a, b):
    a_score = get_score(a)
    b_score = get_score(b)
    return 1 if a_score > b_score else -1

def mkdir(dirp):
    if not os.path.exists(dirp):
        os.makedirs(dirp)

def check_so_file():
    for SO_file in SO.values():
        if not os.path.exists(SO_file):
            # Maybe updating now.. please wait
            logger.debug("Cannot find pintool. Maybe updating?")
            time.sleep(3 * 60)

        if not os.path.exists(SO_file):
            FATAL("Cannot find SO file!")

def get_afl_cmd(fuzzer_stats):
    with open(fuzzer_stats) as f:
        for l in f:
            if l.startswith("command_line"):
                # format= "command_line: [cmd]"
                return l.split(":")[1].strip().split()


class AFLExecutorState(object):
    def __init__(self):
        self.hang = set()
        self.processed = set()
        self.timeout = DEFAULT_TIMEOUT
        self.done = set()
        self.index = 0
        self.num_error_reports = 0
        self.num_crash_reports = 0
        self.crashes = {}

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __getstate__(self):
        return self.__dict__

    def clear(self):
        self.hang = set()
        self.processed = set()

    def increase_timeout(self):
        old_timeout = self.timeout
        if self.timeout < MAX_TIMEOUT:
            self.timeout *= 2
            logger.debug("Increase timeout %d -> %d"
                         % (old_timeout, self.timeout))
        else:
            # Something bad happened, but wait until AFL resolves it
            logger.debug("Hit the maximum timeout")
            # Back to default timeout not to slow down fuzzing
            self.timeout = DEFAULT_TIMEOUT

        # sleep for a minutes to wait until AFL resolves it
        time.sleep(60)

        # clear state for restarting
        self.clear()

    def tick(self):
        old_index = self.index
        self.index += 1
        return old_index

    def get_num_processed(self):
        return len(self.processed) + len(self.hang) + len(self.done)

class AFLExecutor(object):
    def __init__(self, cmd, output, afl, name, filename=None, mail=None, asan_bin=None):
        self.cmd = cmd
        self.output = output
        self.afl = afl
        self.name = name
        self.filename = ".cur_input" if filename is None else filename
        self.mail = mail
        self.set_asan_cmd(asan_bin)

        #**************************
        self.addrlist = set()
        #self.dict Truebranch map,OPcode==>rewrite code
	    #NOP is '90', 8 bits 1 byte
	    #Make a table of these two mappings and write them in the paper
        self.trueBranchMap = {
	    '7f': '9090', '7e': '9090', '7d': '9090', '7c': '9090', '7b': '9090', 
	    '7a': '9090', '79': '9090', '78': '9090', '77': '9090', '76': '9090', 
	    '75': '9090', '74': '9090', '73': '9090', '72': '9090', '71': '9090',
	    '70': '9090', 'e3': '9090',
	    '0f89' : '909090909090', '0f88' : '909090909090', '0f87' : '909090909090',
	    '0f86' : '909090909090', '0f85' : '909090909090', '0f84' : '909090909090',
	    '0f83' : '909090909090', '0f82' : '909090909090', '0f81' : '909090909090',
	    '0f80' : '909090909090', '0f8f' : '909090909090', '0f8e' : '909090909090',
	    '0f8d' : '909090909090', '0f8c' : '909090909090', '0f8b' : '909090909090',
	    '0f8a' : '909090909090'
	    }
        #trsansform to jmp instruction machine code
	    #jmp rel8 : eb
	    #jmp rel32 : e9
        self.falseBranchMap = {
	    '7f': 'eb', '7e': 'eb', '7d': 'eb', '7c': 'eb', '7b': 'eb', 
	    '7a': 'eb', '79': 'eb', '78': 'eb', '77': 'eb', '76': 'eb', 
	    '75': 'eb', '74': 'eb', '73': 'eb', '72': 'eb', '71': 'eb',
	    '70': 'eb', 'e3': 'eb',
	    '0f89' : 'e990', '0f88' : 'e990', '0f87' : 'e990',
	    '0f86' : 'e990', '0f85' : 'e990', '0f84' : 'e990',
	    '0f83' : 'e990', '0f82' : 'e990', '0f81' : 'e990',
	    '0f80' : 'e990', '0f8f' : 'e990', '0f8e' : 'e990',
	    '0f8d' : 'e990', '0f8c' : 'e990', '0f8b' : 'e990',
	    '0f8a' : 'e990'
	    }
        #**************************

        self.tmp_dir = tempfile.mkdtemp()
        cmd, afl_path, qemu_mode = self.parse_fuzzer_stats()
        self.minimizer = minimizer.TestcaseMinimizer(
            cmd, afl_path, self.output, qemu_mode)
        self.import_state()
        self.make_dirs()
        atexit.register(self.cleanup)

    @property
    def cur_input(self):
        return os.path.realpath(os.path.join(self.my_dir, self.filename))

    @property
    def afl_dir(self):
        return os.path.join(self.output, self.afl)

    @property
    def afl_queue(self):
        return os.path.join(self.afl_dir, "queue")

    @property
    def my_dir(self):
        return os.path.join(self.output, self.name)

    @property
    def my_queue(self):
        return os.path.join(self.my_dir, "queue")

    @property
    def my_hangs(self):
        return os.path.join(self.my_dir, "hangs")

    @property
    def my_errors(self):
        return os.path.join(self.my_dir, "errors")

    @property
    def metadata(self):
        return os.path.join(self.my_dir, "metadata")

    @property
    def bitmap(self):
        return os.path.join(self.my_dir, "bitmap")

    def set_asan_cmd(self, asan_bin):
        symbolizer = ""
        for e in [
                "/usr/bin/llvm-symbolizer",
                "/usr/bin/llvm-symbolizer-3.4",
                "/usr/bin/llvm-symbolizer-3.8"]:
            if os.path.exists(e):
                symbolizer = e
                break
        os.putenv("ASAN_SYMBOLIZER_PATH", symbolizer)
        os.putenv("ASAN_OPTIONS", "symbolize=1")

        if asan_bin and os.path.exists(asan_bin):
            self.asan_cmd = [asan_bin] + self.cmd[1:]
        else:
            self.asan_cmd = None

    def make_dirs(self):
        mkdir(self.tmp_dir)
        mkdir(self.my_queue)
        mkdir(self.my_hangs)
        mkdir(self.my_errors)

    def parse_fuzzer_stats(self):
        cmd = get_afl_cmd(os.path.join(self.afl_dir, "fuzzer_stats"))
        assert cmd is not None
        index = cmd.index("--")
        return cmd[index+1:], os.path.dirname(cmd[0]), '-Q' in cmd

    def import_state(self):
        if os.path.exists(self.metadata):
            with open(self.metadata, "rb") as f:
                self.state = pickle.load(f)
        else:
            self.state = AFLExecutorState()

    def sync_files(self):
        files = []
        for name in os.listdir(self.afl_queue):
            path = os.path.join(self.afl_queue, name)
            if os.path.isfile(path):
                files.append(path)

        files = list(set(files) - self.state.done - self.state.processed)
        return sorted(files,
                      key=functools.cmp_to_key(testcase_compare),
                      reverse=True)

    def run_target(self):
        # Trigger linearlize to remove complicate expressions
        #cmd for Executor is the target bianry file
        q = executor.Executor(self.cmd, self.cur_input, self.tmp_dir, bitmap=self.bitmap, argv=["-l", "1"])
        ret = q.run(self.state.timeout)
        logger.debug("Total=%d s, Emulation=%d s, Solver=%d s, Return=%d"
                     % (ret.total_time,
                        ret.emulation_time,
                        ret.solving_time,
                        ret.returncode))
        return q, ret

    def handle_by_return_code(self, res, fp):
        retcode = res.returncode
        if retcode in [124, -9]: # killed
            shutil.copy2(fp, os.path.join(self.my_hangs, os.path.basename(fp)))
            self.state.hang.add(fp)
        else:
            self.state.done.add(fp)

        # segfault or abort
        if (retcode in [128 + 11, -11, 128 + 6, -6]):
            shutil.copy2(fp, os.path.join(self.my_errors, os.path.basename(fp)))
            self.report_error(fp, res.log)

    def send_mail(self, subject, info, attach=None):
        if attach is None:
            attach = []

        cmd = ["mail"]
        for path in attach:
            cmd += ["-A", path]
        cmd += ["-s", "[qsym-report] %s" % subject]
        cmd.append(self.mail)

        info = copy.copy(info)
        info["CMD"] = " ".join(self.cmd)

        text = "\n" # skip cc
        for k, v in info.iteritems():
            text += "%s\n" % k
            text += "-" * 30 + "\n"
            text += "%s" % v + "\n" * 3
        try:
            devnull = open(os.devnull, "wb")
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=devnull, stderr=devnull)
            proc.communicate(text)
        except OSError:
            pass
        finally:
            devnull.close()

    def check_crashes(self):
        for fuzzer in os.listdir(self.output):
            crash_dir = os.path.join(self.output, fuzzer, "crashes")
            if not os.path.exists(crash_dir):
                continue

            # initialize if it's first time to see the fuzzer
            if not fuzzer in self.state.crashes:
                self.state.crashes[fuzzer] = -1

            for name in sorted(os.listdir(crash_dir)):
                # skip readme
                if name == "README.txt":
                    continue

                # read id from the format "id:000000..."
                num = int(name[3:9])
                if num > self.state.crashes[fuzzer]:
                    self.report_crash(os.path.join(crash_dir, name))
                    self.state.crashes[fuzzer] = num

    def report_error(self, fp, log):
        logger.debug("Error is occured: %s\nLog:%s" % (fp, log))
        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_error_reports >= MAX_ERROR_REPORTS:
            return

        self.state.num_error_reports += 1
        self.send_mail("Error found", {"LOG": log}, [fp])

    def report_crash(self, fp):
        logger.debug("Crash is found: %s" % fp)

        # if no mail, then stop
        if self.mail is None:
            return

        # don't do too much
        if self.state.num_crash_reports >= MAX_CRASH_REPORTS:
            return

        self.state.num_crash_reports += 1
        info = {}
        if self.asan_cmd is not None:
            stdout, stderr = utils.run_command(
                    ["timeout", "-k", "5", "5"] + self.asan_cmd,
                    fp)
            info["STDOUT"] = stdout
            info["STDERR"] = stderr
        self.send_mail("Crash found", info, [fp])

    def export_state(self):
        with open(self.metadata, "wb") as f:
            pickle.dump(self.state, f)

    def cleanup(self):
        try:
            self.export_state()
            #shutil.rmtree(self.tmp_dir)
        except:
            pass

    def handle_empty_files(self):
        if len(self.state.hang) > MIN_HANG_FILES:
            self.state.increase_timeout()
        else:
            logger.debug("Sleep for getting files")
            time.sleep(5)

    def run(self):
        logger.debug("Temp directory=%s" % self.tmp_dir)

        while True:
            files = self.sync_files()

            if not files:
                self.handle_empty_files()
                continue

            for fp in files:
                self.run_file(fp)
                break

    def run_file(self, fp):
        check_so_file()

        # copy the test case
        shutil.copy2(fp, self.cur_input)

        old_idx = self.state.index
        logger.debug("Run qsym: input=%s" % fp)
        #logger.debug("Test logger.debug !!!!!!!!")
        q, ret = self.run_target()
        self.handle_by_return_code(ret, fp)
        self.state.processed.add(fp)

        #*********************// process this round qsym processed jcc addr
        
        #logger.debug("Before process jcc addr :")
        jccaddrfilePath = q.get_jccaddrfile()
        self.processJccAddr(jccaddrfilePath)

        target = os.path.basename(fp)[:len("id:......")]
        num_testcase = 0
        for testcase in q.get_testcases():
            num_testcase += 1
            if not self.minimizer.check_testcase(testcase):
                # Remove if it's not interesting testcases
                os.unlink(testcase)
                continue
            index = self.state.tick()
            filename = os.path.join(
                    self.my_queue,
                    "id:%06d,src:%s" % (index, target))
            shutil.move(testcase, filename)
            logger.debug("Creating: %s" % filename)

        if os.path.exists(q.log_file):
            os.unlink(q.log_file)

        # Remove testcase_dir if it`s empty
        try:
            os.rmdir(q.testcase_directory)
        except Exception:
            pass

        logger.debug("Generate %d testcases" % num_testcase)
        logger.debug("%d testcases are new" % (self.state.index - old_idx))

        self.check_crashes()

    #***************************
    def processJccAddr(self,fileName):
        #logger.debug("Enter processJccAddr !!!!")
        if not os.path.exists(fileName):
            logger.debug("AddressToEdit file not exists !")
            return
        fin = open(fileName,"rb")
        rawData = fin.read()    #bytes
        fin.close()

        iSampleCount = len(rawData)//8
        addrData = set()
        for i in range(iSampleCount):
            llData = struct.unpack("<Q",rawData[i*8:i*8+8])[0] #transform to unsigned long long
            addrData.add(llData)
        #transform to string 
        for addr in addrData:
            self.addrlist.add(hex(addr))
            #logger for debug
            logger.debug("JCC ADDR TO EDIT: "+ hex(addr))
        logger.debug("addrlist size %d" % len(self.addrlist))

    #**************************
    def getObjdumpCmd(self,filename,startAddress,stopAddress):
        cmd = ['objdump','-d']
        cmd.append(filename)
        cmd.append('--start-address='+startAddress)
        cmd.append('--stop-address='+stopAddress)
        return cmd
    
    def addrAdd(self,addr,i):
        hex_str = addr[2:]
        num = int(hex_str,16)
        num+=i
        newAddr = hex(num)
        return newAddr
    
    def dumpAndMap(self,argMap,targetBin):
        machineCode = dict()
        for startAddress in self.addrlist:
            stopAddress = self.addrAdd(startAddress,6)
            objdumpCmd = self.getObjdumpCmd(targetBin,startAddress,stopAddress)
            process = subprocess.Popen(objdumpCmd, shell = False, stdout=subprocess.PIPE)
            output,error = process.communicate()
            #print('output type:') # <type 'str'>
            lineToEdit = output.splitlines()
            #print(lineToEdit[7])#the start addr line
            lineElement = lineToEdit[7].split()
            logger.debug(lineElement)
            if not lineElement[0].startswith(startAddress[2:]):
                logger.debug('objdump dumped wrong address !')
            #machineCode[startAddress]=map[lineElement[1]+lineElement[2]]
            if argMap.has_key(lineElement[1]):
                machineCode[startAddress] = argMap[lineElement[1]]			
            elif argMap.has_key(lineElement[1]+lineElement[2]):
                machineCode[startAddress] = argMap[lineElement[1]+lineElement[2]]
            else:
                logger.debug('JCC instruction machine code match error !')
        return machineCode
    
    def rewrite(self,addrToCode,targetBin):
        gdbProcess = subprocess.Popen(['gdb'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        gdbProcess.stdin.write('set write on\n')
        gdbProcess.stdin.write('file '+targetBin+'\n')
        for addr,code in addrToCode.items():
            setcount = len(code)//2
            for i in range(setcount):
                cmd = 'set variable *(char*)'
                cmd+=self.addrAdd(addr,i)+'=0x'+code[i*2:i*2+2]+'\n'
                gdbProcess.stdin.write(cmd)
                disassCmd = 'disassemble '+addr+'\n'
                gdbProcess.stdin.write(disassCmd)
        gdbProcess.stdin.write('q\n')

    #use objdump and jdb to edit target binary file
    def editBianryFile(self):
        #self.cmd[0] is the target bianry file for Executor
        # self.cmd = ['/home/yk/example/test-no','@@']
        #get file name
        pathElement = self.cmd[0].split('/')
        #pathElement = self.cmd
        targetFile = pathElement[-1]
        sourceFile = self.cmd[0]

        #if cut, return
        if targetFile.startswith("cutTrue-") or targetFile.startswith("cutFalse-"):
            return
        
        #cut True Branch
        pathElement[-1] = "cutTrue-"+targetFile

        str = '/'
        #/home/yk/example/cutTrue-test-no
        trueBranchFile = str.join(pathElement)
        shutil.copy2(sourceFile, trueBranchFile)
        logger.debug("Creating: %s" % trueBranchFile)
        addrToCode = self.dumpAndMap(self.trueBranchMap,trueBranchFile)
        self.rewrite(addrToCode,trueBranchFile)

        #cut false branch
        pathElement[-1]="cutFalse-"+targetFile
        str = '/'
        falseBranchFile = str.join(pathElement)
        shutil.copy2(sourceFile, falseBranchFile)
        logger.debug("Createing: %s" % falseBranchFile)
        addrToCode = self.dumpAndMap(self.falseBranchMap,falseBranchFile)
        self.rewrite(addrToCode,falseBranchFile)


    



        
