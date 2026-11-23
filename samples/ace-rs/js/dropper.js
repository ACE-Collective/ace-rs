var s = new ActiveXObject('WScript.Shell');
function run(c) { return s.Run(c, 0); }
run('cmd /c calc');
