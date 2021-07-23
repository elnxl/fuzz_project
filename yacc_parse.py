#!/usr/bin/env python3

from lexics import tokens
import ply.yacc as yacc

class ASan:
    def __init__(self):
        self.tokens = tokens
        self.error_info = None
        self.error_op = None
        self.callstack_summary = [[]]
        self.address = None
        self.function_name = None
        self.path = None
        self.line = None
        self.pos = None
        self.idx = -1
        self.location = None
        self.hint = None
        self.is_objects = False
        self.is_event = False

    def extend_callstack(self):
        self.callstack_summary.append([])
        self.idx += 1

    def p_all_stacktraces(self, p):
        '''all_stacktraces : error_info error_op callstack location callstack frame_objects_str frame_objects hint
                    | error_info error_op callstack located_region operation callstack
                    | error_info error_op callstack located_region operation callstack operation callstack
                    | error_info error_op callstack located_region
                    | leak_sanitizer
                    | error_info error_op callstack'''

        p[0] = ''.join(p[1:])

    def p_leak_sanitizer(self, p):
        '''leak_sanitizer : error_info leak callstack
                          | leak_sanitizer leak callstack'''

        p[0] = ''.join(p[1:])    

    def p_error_info(self, p):
        # handles '==9470==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff8f4f1830 at pc 0x00000052185a bp 0x7fff8f4f1670 sp 0x7fff8f4f0e38'
        # handles '==9464==ERROR: LeakSanitizer: detected memory leaks'
        '''error_info : EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE SANITIZER_DESC SPACE ASCII SPACE ASCII SPACE ADDRESS\
                        SPACE ASCII SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS NEWLINE
                      | EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE ASCII SPACE ASCII SPACE ASCII NEWLINE'''

        if len(p) == 16:
            self.error_info = {'sanitizer': 'AddressSanitizer', 'error type': ''.join(p[9:]).strip()}   
        else: 
            self.error_info = {'sanitizer': 'AddressSanitizer','error type': p[10], 'error address': p[16], 'registers state': {'pc': p[22], 'bp': p[26], 'sp': p[30]}}
        p[0] = ''.join(p[1:])

        self.callstack_summary[0].append(self.error_info)

    def p_error_op(self, p):
        # handles 'WRITE of size 405 at 0x7fff8f4f1830 thread T0'
        '''error_op : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII NEWLINE SPACES'''

        self.idx += 1
        self.error_op = {'type': 'sanitizer header','operation': p[1], 'size': p[7], 'address': p[11], 'thread': p[15]}
        self.callstack_summary[self.idx].append(self.error_op)

        p[0] = ''.join(p[1:])

    def p_callstack(self, p):
        '''callstack : callstack_elem
                     | callstack callstack_elem'''

        if p[0] != None:
            p[0] += + ''.join(p[1:])
        else:
            p[0] = ''.join(p[1:])

        if self.is_event:
            if not self.line:
                self.callstack_summary[self.idx][-1].append({"address": self.address, "function": self.function_name})
            else:
                self.callstack_summary[self.idx][-1].append({"address": self.address, "function": self.function_name, "file": {"path": self.path, "line": self.line, "position": self.pos}})
        else:
            if not self.line:
                self.callstack_summary[self.idx].append({"address": self.address, "function": self.function_name})
            else:
                self.callstack_summary[self.idx].append({"address": self.address, "function": self.function_name, "file": {"path": self.path, "line": self.line, "position": self.pos}})
        
        self.line = None; self.pos = None


    def p_callstack_elem(self, p):
        '''callstack_elem : HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE SPACES
                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE SPACES
                          | HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE
                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE
                          | HASH NUMBER SPACE ADDRESS SPACE FUNCTION place
                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place'''

        p[0] = ''.join(p[1:])

        self.address = p[4]

        if len(p) == 13 or len(p) == 11 or len(p) == 12:
            self.function_name = p[8]
        else:
            self.function_name = p[6][3:]

        if self.function_name[-1] == ' ':
            self.function_name = self.function_name[:-1]

    def p_place(self, p):
        '''place : PATH FILENAME COLON NUMBER COLON NUMBER
                 | PATH FILENAME COLON NUMBER
                 | LPAREN PATH ASCII PLUS ADDRESS RPAREN'''

        p[0] = ''.join(p[1:])

        if p[1] == '(':
            self.path = p[2] + p[3]
        else:
            self.path = p[1] + p[2]

        if p[3] == ':':
            if len(p) == 7:
                self.line = int(p[4])
                self.pos = int(p[6])
            else:
                self.line = int(p[4])
                self.pos = '?'

    def p_location(self, p):
        # handles the strings like 'Address 0x7fff8f4f1830 is located in stack of thread T0 at offset 432 in frame'
        '''location : ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII\
                      SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII\
                      SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII NEWLINE SPACES'''

        self.extend_callstack()

        self.location = {'type': 'stack location','address': p[3], 'located in': p[11], 'thread': p[17], 'offset': p[23]}
        self.callstack_summary[self.idx].append(self.location)

        p[0] = ''.join(p[1:])

    def p_located_region(self, p):
        # handles '0x614000000040 is located 0 bytes inside of 400-byte region [0x614000000040,0x6140000001d0)'
        # handles '0x604000003738 is located 0 bytes to the right of 40-byte region [0x604000003710,0x604000003738)'
        # handles '0x000000f073d0 is located 0 bytes to the right of global variable 'global_array' defined in 'global_overflow.cpp:5:5' (0xf07380) of size 80'
        # handles 'Address 0x604000003a4c is a wild pointer.'
        '''located_region : ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII\
                            SPACE ASCII SPACE NUMBER MINUS ASCII SPACE ASCII SPACE range
                          | ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII\
                            SPACE ASCII SPACE ASCII SPACE ASCII SPACE NUMBER MINUS ASCII SPACE\
                            ASCII SPACE range
                          | ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII\
                            SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE STRING\
                            SPACE LPAREN ADDRESS RPAREN SPACE ASCII SPACE ASCII SPACE NUMBER
                          | ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII DOT
                          | located_region NEWLINE'''

        self.extend_callstack()
        self.callstack_summary[self.idx].append({'type': 'region location','error description': ''.join(p[1:]).strip()})

        p[0] = ''.join(p[1:])

    def p_range(self, p):
        '''range : LBRACK ADDRESS COMA ADDRESS RPAREN
                 | LBRACK ADDRESS COMA ADDRESS RBRACK
                 | LPAREN ADDRESS COMA ADDRESS RPAREN
                 | LPAREN ADDRESS COMA ADDRESS RBRACK
                 | LBRACK NUMBER COMA SPACE NUMBER RPAREN
                 | LBRACK NUMBER COMA SPACE NUMBER RBRACK
                 | LPAREN NUMBER COMA SPACE NUMBER RPAREN
                 | LPAREN NUMBER COMA SPACE NUMBER RBRACK'''

        p[0] = ''.join(p[1:])

    def p_operation(self, p):
        # handles 'freed by thread T0 here:' and 'previously allocated by thread T0 here:'
        '''operation : ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACES
                     | ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACES'''

        # self.extend_callstack()

        self.callstack_summary[self.idx].append([])
        self.is_event = True

        if len(p) == 13:
            self.callstack_summary[self.idx][-1].append({'event': p[1], 'thread': p[7]})
        else:
            self.callstack_summary[self.idx][-1].append({'event': p[3], 'thread': p[9]})

        p[0] = ''.join(p[1:])   

    def p_frame_objects_str(self, p):
        # handles 'This frame has 1 object(s):'
        '''frame_objects_str : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII\
                               LPAREN ASCII RPAREN COLON NEWLINE SPACES'''

        p[0] = ''.join(p[1:])

    def p_frame_objects(self, p):
        '''frame_objects : frame_objects frame_object
                         | frame_object'''

        p[0] = ''.join(p[1:])

    def p_frame_object(self, p):
        # handles '[32, 432) 'stack_array' (line 7) <== Memory access at offset 432 overflows this variable'
        '''frame_object : range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE
                         | range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE SPACES'''

        p[0] = ''.join(p[1:])

        if not self.is_objects:
            self.extend_callstack()
            self.is_objects = True

        self.callstack_summary[self.idx].append({'type': 'frame object', 'range': p[1], 'location': p[3], 'line': p[8], 'error description': p[11][4:]})

    def p_hint(self, p):
        # handles 'HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork (longjmp and C++ exceptions *are* supported)'
        '''hint : HINT COLON SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII\
                  SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COMA SPACE ASCII\
                  SPACE ASCII SPACE ASCII NEWLINE SPACES LPAREN ASCII SPACE ASCII SPACE ASCII PLUS PLUS SPACE ASCII SPACE TIMES\
                  ASCII TIMES SPACE ASCII RPAREN'''
        
        p[0] = ''.join(p[1:])

        self.extend_callstack()
        self.hint = ''.join(p[4:]).replace('\n', '').replace('      ', ' ')
        self.callstack_summary[self.idx].append({'type': 'hint', 'description': self.hint})

    def p_leak(self, p):
        # handles 'Direct leak of 32 byte(s) in 1 object(s) allocated from:'
        '''leak : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN\
                  SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN SPACE ASCII SPACE\
                  ASCII COLON NEWLINE SPACES'''

        p[0] = ''.join(p[1:])

        self.extend_callstack()
        self.callstack_summary[self.idx].append({'type': 'leak', 'size': p[7], 'objects': p[16], 'event': p[23]})

    def p_error(self, p):
        print('Unexpected token:', p)

    def parse_data(self, data):
        parser = yacc.yacc(module=self)
        parser.parse(data)

    def get_info(self):
        if self.callstack_summary[-1] == []:
            self.callstack_summary.pop()

        return self.callstack_summary

class UBSan:
    def __init__(self):
        self.tokens = tokens
        self.callstack_summary = []
        self.address = None
        self.function_name = None
        self.path = None
        self.line = None
        self.pos = None
        self.error_desc = {"file": {"filename": None, "line": None, "position": None}, "error type": None}

    def p_info(self, p):
        '''info : desc callstack
                | desc'''
        
        p[0] = ''.join(p[1:])

    def p_desc(self, p):
        '''desc : FILENAME COLON NUMBER COLON NUMBER COLON SPACE ERROR_TYPE NEWLINE SPACES
                | FILENAME COLON NUMBER COLON NUMBER COLON SPACE ERROR_TYPE NEWLINE
                | FILENAME COLON NUMBER COLON NUMBER COLON SPACE ERROR_TYPE'''

        p[0] = ''.join(p[1:])
        
        self.error_desc['file']['filename'] = p[1]
        self.error_desc['file']['line'] = p[3]
        self.error_desc['file']['position'] = p[5]
        self.error_desc['error type'] = p[8][p[8].find(': ')+2:]

        self.callstack_summary.append(self.error_desc)

    def p_callstack(self, p):
        '''callstack : callstack_elem
                     | callstack callstack_elem'''

        if p[0] != None:
            p[0] = p[0] + ''.join(p[1:])
        else:
            p[0] = ''.join(p[1:])

        if not self.line:
            self.callstack_summary.append({"address": self.address, "function": self.function_name})
        else:
            self.callstack_summary.append({"address": self.address, "function": self.function_name, "file": {"path": self.path, "line": self.line, "position": self.pos}})
        
        self.line = None; self.pos = None


    def p_callstack_elem(self, p):
        '''callstack_elem : HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE SPACES
                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE SPACES
                          | HASH NUMBER SPACE ADDRESS SPACE FUNCTION place
                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place'''

        p[0] = ''.join(p[1:])

        self.address = p[4]

        if len(p) == 13 or len(p) == 11 or len(p) == 12:
            self.function_name = p[8]
        else:
            self.function_name = p[6][3:]

        if self.function_name[-1] == ' ':
            self.function_name = self.function_name[:-1]

    def p_place(self, p):
        '''place : PATH FILENAME COLON NUMBER COLON NUMBER
                 | PATH FILENAME COLON NUMBER
                 | LPAREN PATH ASCII PLUS ADDRESS RPAREN'''

        p[0] = ''.join(p[1:])

        if p[1] == '(':
            self.path = p[2] + p[3]
        else:
            self.path = p[1] + p[2]

        if p[3] == ':':
            if len(p) == 7:
                self.line = int(p[4])
                self.pos = int(p[6])
            else:
                self.line = int(p[4])
                self.pos = '?'

    def p_error(self, p):
        print('Unexpected token:', p)

    def parse_data(self, data):
        parser = yacc.yacc(module=self)
        parser.parse(data)

    def get_info(self):
        return self.callstack_summary