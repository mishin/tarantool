-- test for xlog_reader module
-- consists of 3 parts:
-- 1) ok snap/xlog reader
-- 2) broken files reader (crc sum is invalid, bad header [version/type])
-- 3) before box.cfg and after box.cfg

fio  = require('fio')
fun  = require('fun')
json = require('json')
xlog = require('xlog').pairs
trun = require('test_run').new()

-- OK test

pattern_ok_v12 = "../box/xlog_reader/v12/*.ok.*"
pattern_ok_v13 = "../box/xlog_reader/v13/*.ok.*"
fio.cwd();

trun:cmd("setopt delimiter ';'")
function collect_results(file)
    local val = {}
    for k, v in xlog(file) do
        table.insert(val, json.encode(v))
    end
    return file, val
end;
trun:cmd("setopt delimiter ''");

fun.iter(fio.glob(pattern_ok_v12)):map(collect_results):tomap();
fun.iter(fio.glob(pattern_ok_v13)):map(collect_results):tomap();

collect_results("../box/xlog_reader/version.bad.xlog")
collect_results("../box/xlog_reader/format.bad.xlog")
collect_results("../box/xlog_reader/crc.bad.xlog")
