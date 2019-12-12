{$M 8192,0,0}

Program IPS_Translate;

uses Dos, Crt;

type
  ScreenType = array[0..3999] of Byte;

const
  IPSHeader = 'PATCH';
  AddressBytes = 3;
  MaxArraySize =  50000;

var
  Screen         : ScreenType absolute $B800:0000;
  SourceName     : string;
  PatchName      : string;
  PatchFile      : file;
  SourceFile     : file;
  f              : file;
  LogFile        : text;
  header         : array[1..5] of char;
  AddArray       : array[1..3] of byte;
  RLEArray       : array[1..3] of byte;
  BytesArray     : array[1..2] of byte;
  ChunkArray     : array[1..MaxArraySize] of byte;
  Address        : longint;
  NumBytes       : longint;
  RLEBytes       : longint;
  RLEByte        : byte;
  Count          : longint;
  TotalChunks    : integer;
  a1,a2,a3       : longint;
  h1,h2,h3       : string;
  s              : string;
  message        : string;
  Verbose,Backup : boolean;
  Exist          : boolean;
  Overload       : boolean;


Procedure CloseFiles;
  begin
    if verbose = true then
      begin
        WriteLn(LogFile, 'ÀÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÙ');
        Writeln(LogFile);
        Writeln(LogFile,'Total Chunks:  ',totalchunks);
      end;
    Close(SourceFile);
    Close(PatchFile);
    If Verbose = True then
      Close(LogFile);
    GotoXY(53,13);
    TextColor (White);
    WriteLn('Patching Complete !!!');
    GotoXY(1,20);
    If Overload = True then
      begin
        TextColor(LightGray);
        Writeln('The patch file has requested a patch size greater then the');
        WriteLn('maximum patch size this version can handle.  The maximum');
        WriteLn('patch size is currently set to ',MaxArraySize);
        WriteLn;
      end;
    halt;
  end;

Procedure exit_program;
  {$I IPS.SCR}
  begin
    Move(ImageData,Screen,4000);
    GotoXY(1,19);
    If Exist = False then
    begin
      WriteLn (s,' Not Found!');
    end;
    If Message <> '' then
      writeln(message);
    halt;
  end;

Function Hex(the_Byte:byte):String;
  var
    code       : integer;
    low,high   : integer;
    lowH,highH : string[1];
  begin
    low := (the_byte and 15);
    high := (the_byte and 240);
    high := high div 16;
    case low of
      10 : lowH := 'A';
      11 : lowH := 'B';
      12 : lowH := 'C';
      13 : lowH := 'D';
      14 : lowH := 'E';
      15 : lowH := 'F'
    else
      str(low,lowH);
    end;

    case high of
      10 : highH := 'A';
      11 : highH := 'B';
      12 : highH := 'C';
      13 : highH := 'D';
      14 : highH := 'E';
      15 : highH := 'F'
    else
      str(high,highH);
    end;

    Hex := highH+lowH;
  end;

Procedure Display_Stuff;
  begin
    TextColor(LightGreen);
    GotoXY(70,11);
    Write(TotalChunks:4);
    GotoXY (22,13);
    Write (Address:8);
    GotoXY (46,11);
    If NumBytes <> 0
    then
      Write (NumBytes:5)
    else
      Write (RLEBytes:5);
    if Verbose = True
    then
      if NumBytes <> 0
      then
        Writeln(LogFile, NumBytes:5, ' ³          ³')
      else
        Writeln;
  end;

Procedure IsItAnIPS;
  var
    checksum : integer;
  begin
    Blockread(PatchFile,Header,SizeOf(Header));
    If Header <> IPSHeader then
      begin
        Writeln;
        Writeln;
        Writeln('Your patch file is not a valid IPS');
        Writeln;
        halt;
      end;
  end;

Procedure GetAddress;
  begin
    BlockRead(PatchFile,AddArray,3);
    if (AddArray[1] = 69) and (AddArray[2] = 79) and (AddArray[3] = 70) then
      CloseFiles;
    Inc(TotalChunks,1);
    h1:=''; h2:=''; h3:='';
    h1 := hex(AddArray[1]);
    h2 := hex(AddArray[2]);
    h3 := hex(AddArray[3]);
    a1 := AddArray[1];
    a2 := AddArray[2];
    a3 := AddArray[3];
    Address := a3;
    Address := Address + (a2 * 256);
    Address := Address + (a1 * 65536);
    TextColor(LightGreen);
    GotoXY (22,11);
    s := h1+h2+h3;
    Write(s:6);
    If Verbose = true then
      begin
        Write (LogFile,'³',Address:8,'  ³ ');
        Write (LogFile,s:7,'  ³ ');
      end;
  end;

Procedure GetRLE;
  var
    r1,r2 : longint;
  begin
    BlockRead(PatchFile,RLEArray,3);
    r1 := RLEArray[1];
    r2 := RLEArray[2];
    RLEBytes := r2;
    RLEBytes := RLEBytes + r1 * 256;
    RLEByte  := RLEArray[3];
    if Verbose = true then
      begin
        Write(LogFile, RLEBytes:5, ' ³ ');
        WriteLn(LogFile, '   ',RLEByte:3, '   ³');
      end;
  end;

Procedure GetNumBytes;
  var
    b1,b2 : longint;
  begin
    BlockRead(PatchFile,BytesArray,2);
    b1 := BytesArray[1];
    b2 := BytesArray[2];
    NumBytes := b2;
    NumBytes := NumBytes + b1 * 256;
    if NumBytes = 0 then
      GetRLE;
    if NumBytes > MaxArraySize then
      begin
        Overload := True;
        Display_Stuff;
        CloseFiles
      end;
  end;

Procedure GetChunk;
  begin
    BlockRead(PatchFile,ChunkArray,NumBytes);
  end;

Procedure ApplyPatch;
  begin
    Seek(SourceFile,Address);
    BlockWrite (SourceFile, ChunkArray, NumBytes);
  end;

Procedure ApplyRLE;
  begin
    Seek(SourceFile,Address);
    if RLEBytes > MaxArraySize then
      begin
        for count := 1 to MaxArraySize do
          ChunkArray[count] := RLEByte;
        BlockWrite (SourceFile, ChunkArray, MaxArraySize);
        RLEBytes := RLEBytes - MaxArraySize;
      end;
    for count := 1 to RLEBytes do
      ChunkArray[count] := RLEByte;
    BlockWrite (SourceFile, ChunkArray, RLEBytes);
  end;

Procedure Backup_Source;
  begin
    TextColor(Yellow);
    GotoXY(53,13);
    Write('Copying Source');
    SwapVectors;
    Exec(GetEnv('COMSPEC'), '/c copy ' + SourceName + ' SRC_BAK.TMP > nul');
    SwapVectors;
  end;

Procedure Display_Main;
  {$I IPSMAIN.SCR}
  begin
    Move(MainData,Screen,4000);
    TextBackground(Black);
    TextColor (LightCyan);
    GotoXY(22,7);
    Write(SourceName);
    GotoXY(22,9);
    Write(PatchName);
  end;

(**************************************************************************)

begin
  Exist := True;
  Verbose := False;
  Backup  := False;
  TotalChunks := 0;
  Overload := False;
  message := '';

  If (ParamCount < 2) or (ParamCount > 4) then
    exit_program;

  SourceName := ParamStr(1);
  for count := 1 to length(SourceName) do
    SourceName[count] := Upcase(SourceName[count]);
  {$I-}
  Assign(f, SourceName);
  Reset(f);
  Close(f);
  {$I+}
  if IOResult <> 0 then
    begin
      Exist := False;
      s := SourceName;
      exit_Program
    end;
  If SourceName[1] = '/' then
    exit_program;
  Assign (SourceFile, SourceName);
  Reset (SourceFile,1);
  PatchName := ParamStr(2);
  for count := 1 to length(PatchName) do
    PatchName[count] := Upcase(PatchName[count]);
  {$I-}
  Assign(f, PatchName);
  Reset(f);
  Close(f);
  {$I+}
  if IOResult <> 0 then
    begin
      Exist := False;
      s:=PatchName;
      exit_Program
    end;
  If PatchName[1] = '/' then
    exit_program;
  If SourceName = PatchName then
    begin
      message := 'Source file and Patch file MUST be different!!';
      exit_program
    end;
  Assign  (PatchFile,  PatchName);
  Reset   (PatchFile,1);

  If ParamCount >= 3 then
    begin
      s := ParamStr(3);
      if (s = '/l') or (s = '/L') then
        Verbose := True;
      if (s = '/b') or (s = '/B') then
        Backup := True;
    end;

  If ParamCount = 4 then
    begin
      s := ParamStr(4);
      if (s = '/l') or (s = '/L') then
        Verbose := True;
      if (s = '/b') or (s = '/B') then
        Backup := True;
    end;

  IsItAnIPS;

  Display_Main;

  If Backup = True then
    Backup_Source;

  If Verbose = True then
    begin
      TextColor(LightMagenta);
      gotoXY(53,13);
      Write('Creating log file');
      Assign(LogFile,'LOGFILE.TXT');
      ReWrite(LogFile);
      Writeln(LogFile);
      Writeln(LogFile,'Created with International Patch Translator PLUS v1.2');
      WriteLn(LogFile,'Presented by the WaveMaster.  $CePTiC, 1993');
      WriteLn(LogFile,'Call Spatula City: 707-451-2835');
      WriteLn(LogFile);
      Write(LogFile,'Source File: ');
      WriteLn(LogFile,SourceName);
      Write(LogFile,'Patch File : ');
      WriteLn(LogFile,PatchName);
      WriteLn(LogFile);
      WriteLn(LogFile, 'ÚÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄ¿');
      WriteLn(LogFile, '³ ADDR dec ³ ADDR hex ³ Bytes ³ RLE byte ³');
      WriteLn(LogFile, 'ÃÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄ´');
    end;

  While not EOF(PatchFile) do
  begin
    GetAddress;
    GetNumBytes;
    Display_Stuff;
    If NumBytes <> 0
    then
      GetChunk;
    If NumBytes <> 0
    then
      ApplyPatch
    else
      ApplyRLE;
  end;

  CloseFiles;

end.
