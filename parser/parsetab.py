
# parsetab.py
# This file is automatically generated. Do not edit.
# pylint: disable=W,C,R
_tabversion = '3.10'

_lr_method = 'LALR'

_lr_signature = 'ADDRESS ASCII COLON COMA DOT EQUAL ERROR_TYPE FILENAME FUNCTION HASH HINT LBRACK LPAREN MINUS MSG NEWLINE NUMBER PATH PLUS RBRACK RPAREN SANITIZER SANITIZER_DESC SPACE SPACES STRING TIMESall_stacktraces : error_info error_op callstack location callstack frame_objects_str frame_objects hint\n                    | error_info error_op callstack located_region operation callstack\n                    | error_info error_op callstack located_region operation callstack operation callstack\n                    | error_info error_op callstack located_region\n                    | leak_sanitizer\n                    | error_info error_op callstackleak_sanitizer : error_info leak callstack\n                          | leak_sanitizer leak callstackerror_info : EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE SANITIZER_DESC SPACE ASCII SPACE ASCII SPACE ADDRESS                        SPACE ASCII SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS NEWLINE\n                      | EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE ASCII SPACE ASCII SPACE ASCII NEWLINEerror_op : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII NEWLINE SPACEScallstack : callstack_elem\n                     | callstack callstack_elemcallstack_elem : HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE SPACES\n                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE SPACES\n                          | HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE\n                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE\n                          | HASH NUMBER SPACE ADDRESS SPACE FUNCTION place\n                          | HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE placeplace : PATH FILENAME COLON NUMBER COLON NUMBER\n                 | PATH FILENAME COLON NUMBER\n                 | LPAREN PATH ASCII PLUS ADDRESS RPARENlocation : ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII                      SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII                      SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII NEWLINE SPACESlocated_region : ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII                            SPACE ASCII SPACE NUMBER MINUS ASCII SPACE ASCII SPACE range\n                          | ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII                            SPACE ASCII SPACE ASCII SPACE ASCII SPACE NUMBER MINUS ASCII SPACE                            ASCII SPACE range\n                          | ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII                            SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE STRING                            SPACE LPAREN ADDRESS RPAREN SPACE ASCII SPACE ASCII SPACE NUMBER\n                          | ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII DOT\n                          | located_region NEWLINErange : LBRACK ADDRESS COMA ADDRESS RPAREN\n                 | LBRACK ADDRESS COMA ADDRESS RBRACK\n                 | LPAREN ADDRESS COMA ADDRESS RPAREN\n                 | LPAREN ADDRESS COMA ADDRESS RBRACK\n                 | LBRACK NUMBER COMA SPACE NUMBER RPAREN\n                 | LBRACK NUMBER COMA SPACE NUMBER RBRACK\n                 | LPAREN NUMBER COMA SPACE NUMBER RPAREN\n                 | LPAREN NUMBER COMA SPACE NUMBER RBRACKoperation : ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACES\n                     | ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACESframe_objects_str : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII                               LPAREN ASCII RPAREN COLON NEWLINE SPACESframe_objects : frame_objects frame_object\n                         | frame_objectframe_object : range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE\n                         | range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE SPACEShint : HINT COLON SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII                  SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COMA SPACE ASCII                  SPACE ASCII SPACE ASCII NEWLINE SPACES LPAREN ASCII SPACE ASCII SPACE ASCII PLUS PLUS SPACE ASCII SPACE TIMES                  ASCII TIMES SPACE ASCII RPARENleak : ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN                  SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN SPACE ASCII SPACE                  ASCII COLON NEWLINE SPACES'
    
_lr_action_items = {'EQUAL':([0,10,],[4,18,]),'$end':([1,3,11,12,14,16,20,21,30,40,62,71,90,107,117,118,120,121,127,137,138,139,140,145,147,160,172,173,174,185,259,283,309,338,],[0,-5,-6,-12,-7,-8,-4,-13,-28,-2,-1,-3,-18,-16,-31,-32,-29,-30,-14,-35,-36,-33,-34,-21,-19,-17,-20,-22,-15,-27,-24,-25,-26,-44,]),'ASCII':([2,3,11,12,14,15,16,17,18,20,21,28,30,33,35,36,40,41,53,56,57,58,72,86,88,90,93,94,95,96,97,104,107,109,116,117,118,120,121,125,126,127,132,133,134,135,137,138,139,140,142,145,147,154,156,157,160,161,163,164,165,168,172,173,174,176,181,184,185,186,187,189,191,205,206,209,210,218,223,224,225,227,228,233,236,237,238,241,249,250,251,253,254,255,259,265,266,268,275,279,280,283,287,291,297,298,299,303,304,308,309,311,314,316,318,322,324,326,330,333,336,],[7,9,22,-12,-7,25,-8,26,27,31,-13,39,-28,43,45,46,31,55,70,73,74,76,87,103,105,-18,110,111,112,113,115,124,-16,129,136,-31,-32,-29,-30,143,144,-14,149,150,151,152,-35,-36,-33,-34,155,-21,-19,167,170,171,-17,175,177,178,179,182,-20,-22,-15,188,193,196,-27,197,198,-10,201,214,215,219,220,226,230,231,232,234,235,239,242,243,245,248,256,257,258,260,261,262,-24,271,272,274,281,285,286,-25,292,295,301,-9,302,305,306,310,-26,312,315,317,319,323,325,327,331,334,337,]),'NUMBER':([4,13,51,52,59,60,89,100,102,123,128,153,158,199,206,237,263,307,],[10,24,67,69,77,78,106,119,122,141,145,166,172,208,216,244,269,309,]),'HASH':([5,6,8,11,12,14,16,19,21,28,29,40,54,71,90,107,127,145,147,160,172,173,174,195,213,217,289,300,],[13,13,13,13,-12,13,13,13,-13,13,13,13,13,13,-18,-16,-14,-21,-19,-17,-20,-22,-15,-37,-38,-11,-45,-23,]),'SPACE':([7,9,22,23,24,25,26,31,37,39,42,43,44,45,46,50,55,70,73,74,76,77,78,79,80,81,83,85,87,103,105,106,110,111,113,114,115,117,118,120,121,124,136,137,138,139,140,141,143,144,148,150,151,152,155,162,170,171,175,178,179,180,188,196,197,200,201,208,214,215,219,220,230,231,232,234,235,242,243,245,246,247,248,256,257,258,260,261,262,269,270,271,273,274,281,285,286,293,295,301,302,305,306,310,313,315,317,323,325,329,331,335,],[15,17,32,33,34,35,36,41,47,53,56,57,58,59,60,65,72,86,88,89,93,94,95,96,97,98,100,102,104,123,125,126,130,131,133,134,135,-31,-32,-29,-30,142,153,-35,-36,-33,-34,154,156,157,161,163,164,165,168,176,184,186,187,190,191,192,199,205,206,209,210,218,223,224,227,228,236,237,238,240,241,249,250,252,253,254,255,263,264,265,266,267,268,275,276,277,279,280,287,290,291,297,299,303,304,307,308,311,314,316,318,324,326,330,332,336,]),'ADDRESS':([11,12,21,32,34,51,52,82,84,90,107,127,131,145,146,147,160,172,173,174,190,240,267,282,290,],[23,-12,-13,42,44,66,68,99,101,-18,-16,-14,148,-21,159,-19,-17,-20,-22,-15,200,247,273,288,294,]),'NEWLINE':([20,30,90,117,118,120,121,137,138,139,140,145,147,169,172,173,177,185,194,198,202,212,259,278,283,292,294,309,319,],[30,-28,107,-31,-32,-29,-30,-35,-36,-33,-34,-21,160,183,-20,-22,189,-27,204,207,211,222,-24,284,-25,296,298,-26,320,]),'COLON':([27,61,64,108,145,155,182,203,272,],[37,79,80,128,158,169,194,212,278,]),'LBRACK':([38,48,49,63,211,221,229,252,277,],[52,52,-41,-40,-42,-43,-39,52,52,]),'LPAREN':([38,48,49,63,75,98,111,112,130,167,211,221,226,229,252,276,277,321,],[51,51,-41,-40,92,116,132,132,92,181,-42,-43,233,-39,51,282,51,322,]),'SANITIZER':([47,],[61,]),'HINT':([48,49,63,211,221,],[64,-41,-40,-42,-43,]),'FUNCTION':([58,],[75,]),'STRING':([65,264,],[81,270,]),'COMA':([66,67,68,69,312,],[82,83,84,85,313,]),'PATH':([75,92,130,],[91,109,91,]),'FILENAME':([91,],[108,]),'SANITIZER_DESC':([96,],[114,]),'RPAREN':([99,101,119,122,149,159,166,193,239,288,337,],[117,120,137,139,162,173,180,203,246,293,338,]),'RBRACK':([99,101,119,122,],[118,121,138,140,]),'SPACES':([107,160,183,204,207,211,222,284,296,320,],[127,174,195,213,217,221,229,289,300,321,]),'PLUS':([129,327,328,],[146,328,329,]),'DOT':([170,],[185,]),'MSG':([192,],[202,]),'MINUS':([216,244,],[225,251,]),'TIMES':([332,334,],[333,335,]),}

_lr_action = {}
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
      if not _x in _lr_action:  _lr_action[_x] = {}
      _lr_action[_x][_k] = _y
del _lr_action_items

_lr_goto_items = {'all_stacktraces':([0,],[1,]),'error_info':([0,],[2,]),'leak_sanitizer':([0,],[3,]),'error_op':([2,],[5,]),'leak':([2,3,],[6,8,]),'callstack':([5,6,8,19,29,54,],[11,14,16,28,40,71,]),'callstack_elem':([5,6,8,11,14,16,19,28,29,40,54,71,],[12,12,12,21,21,21,12,21,12,21,12,21,]),'location':([11,],[19,]),'located_region':([11,],[20,]),'operation':([20,40,],[29,54,]),'frame_objects_str':([28,],[38,]),'frame_objects':([38,],[48,]),'frame_object':([38,48,],[49,63,]),'range':([38,48,252,277,],[50,50,259,283,]),'hint':([48,],[62,]),'place':([75,130,],[90,147,]),}

_lr_goto = {}
for _k, _v in _lr_goto_items.items():
   for _x, _y in zip(_v[0], _v[1]):
       if not _x in _lr_goto: _lr_goto[_x] = {}
       _lr_goto[_x][_k] = _y
del _lr_goto_items
_lr_productions = [
  ("S' -> all_stacktraces","S'",1,None,None,None),
  ('all_stacktraces -> error_info error_op callstack location callstack frame_objects_str frame_objects hint','all_stacktraces',8,'p_all_stacktraces','yacc_parse.py',28),
  ('all_stacktraces -> error_info error_op callstack located_region operation callstack','all_stacktraces',6,'p_all_stacktraces','yacc_parse.py',29),
  ('all_stacktraces -> error_info error_op callstack located_region operation callstack operation callstack','all_stacktraces',8,'p_all_stacktraces','yacc_parse.py',30),
  ('all_stacktraces -> error_info error_op callstack located_region','all_stacktraces',4,'p_all_stacktraces','yacc_parse.py',31),
  ('all_stacktraces -> leak_sanitizer','all_stacktraces',1,'p_all_stacktraces','yacc_parse.py',32),
  ('all_stacktraces -> error_info error_op callstack','all_stacktraces',3,'p_all_stacktraces','yacc_parse.py',33),
  ('leak_sanitizer -> error_info leak callstack','leak_sanitizer',3,'p_leak_sanitizer','yacc_parse.py',38),
  ('leak_sanitizer -> leak_sanitizer leak callstack','leak_sanitizer',3,'p_leak_sanitizer','yacc_parse.py',39),
  ('error_info -> EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE SANITIZER_DESC SPACE ASCII SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ADDRESS NEWLINE','error_info',31,'p_error_info','yacc_parse.py',44),
  ('error_info -> EQUAL NUMBER EQUAL ASCII COLON SPACE SANITIZER COLON SPACE ASCII SPACE ASCII SPACE ASCII NEWLINE','error_info',15,'p_error_info','yacc_parse.py',45),
  ('error_op -> ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII NEWLINE SPACES','error_op',17,'p_error_op','yacc_parse.py',59),
  ('callstack -> callstack_elem','callstack',1,'p_callstack','yacc_parse.py',69),
  ('callstack -> callstack callstack_elem','callstack',2,'p_callstack','yacc_parse.py',70),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE SPACES','callstack_elem',9,'p_callstack_elem','yacc_parse.py',92),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE SPACES','callstack_elem',12,'p_callstack_elem','yacc_parse.py',93),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE FUNCTION place NEWLINE','callstack_elem',8,'p_callstack_elem','yacc_parse.py',94),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place NEWLINE','callstack_elem',11,'p_callstack_elem','yacc_parse.py',95),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE FUNCTION place','callstack_elem',7,'p_callstack_elem','yacc_parse.py',96),
  ('callstack_elem -> HASH NUMBER SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE place','callstack_elem',10,'p_callstack_elem','yacc_parse.py',97),
  ('place -> PATH FILENAME COLON NUMBER COLON NUMBER','place',6,'p_place','yacc_parse.py',112),
  ('place -> PATH FILENAME COLON NUMBER','place',4,'p_place','yacc_parse.py',113),
  ('place -> LPAREN PATH ASCII PLUS ADDRESS RPAREN','place',6,'p_place','yacc_parse.py',114),
  ('location -> ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII NEWLINE SPACES','location',29,'p_location','yacc_parse.py',132),
  ('located_region -> ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII SPACE ASCII SPACE NUMBER MINUS ASCII SPACE ASCII SPACE range','located_region',21,'p_located_region','yacc_parse.py',145),
  ('located_region -> ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE NUMBER MINUS ASCII SPACE ASCII SPACE range','located_region',25,'p_located_region','yacc_parse.py',146),
  ('located_region -> ADDRESS SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE STRING SPACE LPAREN ADDRESS RPAREN SPACE ASCII SPACE ASCII SPACE NUMBER','located_region',33,'p_located_region','yacc_parse.py',147),
  ('located_region -> ASCII SPACE ADDRESS SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII DOT','located_region',12,'p_located_region','yacc_parse.py',148),
  ('located_region -> located_region NEWLINE','located_region',2,'p_located_region','yacc_parse.py',149),
  ('range -> LBRACK ADDRESS COMA ADDRESS RPAREN','range',5,'p_range','yacc_parse.py',166),
  ('range -> LBRACK ADDRESS COMA ADDRESS RBRACK','range',5,'p_range','yacc_parse.py',167),
  ('range -> LPAREN ADDRESS COMA ADDRESS RPAREN','range',5,'p_range','yacc_parse.py',168),
  ('range -> LPAREN ADDRESS COMA ADDRESS RBRACK','range',5,'p_range','yacc_parse.py',169),
  ('range -> LBRACK NUMBER COMA SPACE NUMBER RPAREN','range',6,'p_range','yacc_parse.py',170),
  ('range -> LBRACK NUMBER COMA SPACE NUMBER RBRACK','range',6,'p_range','yacc_parse.py',171),
  ('range -> LPAREN NUMBER COMA SPACE NUMBER RPAREN','range',6,'p_range','yacc_parse.py',172),
  ('range -> LPAREN NUMBER COMA SPACE NUMBER RBRACK','range',6,'p_range','yacc_parse.py',173),
  ('operation -> ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACES','operation',12,'p_operation','yacc_parse.py',178),
  ('operation -> ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COLON NEWLINE SPACES','operation',14,'p_operation','yacc_parse.py',179),
  ('frame_objects_str -> ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN COLON NEWLINE SPACES','frame_objects_str',15,'p_frame_objects_str','yacc_parse.py',195),
  ('frame_objects -> frame_objects frame_object','frame_objects',2,'p_frame_objects','yacc_parse.py',202),
  ('frame_objects -> frame_object','frame_objects',1,'p_frame_objects','yacc_parse.py',203),
  ('frame_object -> range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE','frame_object',12,'p_frame_object','yacc_parse.py',208),
  ('frame_object -> range SPACE STRING SPACE LPAREN ASCII SPACE NUMBER RPAREN SPACE MSG NEWLINE SPACES','frame_object',13,'p_frame_object','yacc_parse.py',209),
  ('hint -> HINT COLON SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII SPACE ASCII COMA SPACE ASCII SPACE ASCII SPACE ASCII NEWLINE SPACES LPAREN ASCII SPACE ASCII SPACE ASCII PLUS PLUS SPACE ASCII SPACE TIMES ASCII TIMES SPACE ASCII RPAREN','hint',58,'p_hint','yacc_parse.py',221),
  ('leak -> ASCII SPACE ASCII SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN SPACE ASCII SPACE NUMBER SPACE ASCII LPAREN ASCII RPAREN SPACE ASCII SPACE ASCII COLON NEWLINE SPACES','leak',28,'p_leak','yacc_parse.py',234),
]
