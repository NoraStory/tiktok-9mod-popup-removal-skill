/*
 * java_trace.js — Frida Java-bridge tracer for mod popups
 *
 * Goal: find out (a) the exact URL the popup content is fetched from,
 * (b) which class/method actually draws the popup.
 *
 * !! FRIDA 17 NOTE (2026-09-30): the Java bridge is NO LONGER bundled in the
 *    frida-core JS runtime. A bare `Java` object is undefined (ReferenceError).
 *    Either run through the frida CLI with a frida-java-bridge capable runtime,
 *    or pin frida 16.x for this script. Verified working path on LDPlayer 14:
 *      frida 16.x server + `frida -D emulator-5554 -f com.zhiliaoapp.musically -l java_trace.js`
 *    On ARM-translation emulators NEVER hook methods executed by native code
 *    (houdini conflict -> SIGSEGV SI_KERNEL); Java-only hooks are safe.
 *
 * Run against the gadget-injected debug build (frida <=16):
 *   adb forward tcp:27042 tcp:27042
 *   frida -H 127.0.0.1:27042 -n Gadget -l java_trace.js
 *
 * NOTE: Class names below are VERSION-SPECIFIC. Update for each version:
 *   - modClasses: me.tiktokupdatez.* (same across v46.3.5/v46.7.5)
 *   - loaderClass: 'prime0.gold' (v46.7.5) / 'probeq0.neonlia' (v46.3.5)
 *                  / 'ieuwh0.yeujser' / 'chillbro0.berusz'
 *   - TikTok obfuscated class names (X.0w1M etc.) change every build
 *   - Use dexscan.py --classes first to discover the actual names
 */
'use strict';

var TAG = '[TRACE]';
var URL_RE = /https?:\/\/|\.txt|\.conf|9mod|tiktokmod|banner|update|imoax|rezvorck/i;

function log(s) { console.log(TAG + ' ' + s); }

function jstack() {
  try {
    var t = Java.use('java.lang.Thread').currentThread();
    var st = t.getStackTrace();
    var out = [];
    for (var i = 0; i < st.length && i < 14; i++) out.push(st[i].toString());
    return out.join('\n        at ');
  } catch (e) { return '<no stack: ' + e + '>'; }
}

function hookAll(clsName, methodNames, opts) {
  opts = opts || {};
  var C;
  try { C = Java.use(clsName); } catch (e) { return false; }
  var n = 0;
  methodNames.forEach(function (m) {
    var overloads;
    try { overloads = C[m].overloads; } catch (e) { return; }
    overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) {
            try { args.push(String(arguments[i]).substring(0, 300)); } catch (e) { args.push('?'); }
          }
          var ret = ov.apply(this, arguments);
          log('CALL ' + clsName + '.' + m + '(' + args.join(', ') + ')' +
              (opts.showRet ? ' => ' + String(ret).substring(0, 300) : ''));
          if (opts.stack) log('     at ' + jstack());
          return ret;
        };
        n++;
      } catch (e) {}
    });
  });
  if (n) log('hooked ' + clsName + ' (' + n + ' overloads)');
  return n > 0;
}

Java.perform(function () {
  log('=== java bridge attached, pid=' + Process.id + ' ===');

  /* ---------------------------------------------------------------- *
   * 1. catch the concatenated URL
   * ---------------------------------------------------------------- */
  try {
    var SB = Java.use('java.lang.StringBuilder');
    SB.toString.implementation = function () {
      var r = this.toString();
      try {
        if (r && URL_RE.test(r) && r.length < 500) {
          log('StringBuilder.toString() => ' + JSON.stringify(String(r)));
          log('     at ' + jstack());
        }
      } catch (e) {}
      return r;
    };
    log('hooked StringBuilder.toString');
  } catch (e) { log('StringBuilder hook failed: ' + e); }

  try {
    var Str = Java.use('java.lang.String');
    Str.concat.implementation = function (s) {
      var r = this.concat(s);
      try {
        if (r && URL_RE.test(r) && r.length < 500) {
          log('String.concat => ' + JSON.stringify(String(r)));
          log('     at ' + jstack());
        }
      } catch (e) {}
      return r;
    };
    log('hooked String.concat');
  } catch (e) { log('String.concat hook failed: ' + e); }

  /* ---------------------------------------------------------------- *
   * 2. network
   * ---------------------------------------------------------------- */
  try {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (s) {
      log('new URL(' + JSON.stringify(String(s)) + ')');
      log('     at ' + jstack());
      return this.$init(s);
    };
    URL.openConnection.overload().implementation = function () {
      log('URL.openConnection ' + this.toString());
      log('     at ' + jstack());
      return this.openConnection();
    };
    log('hooked java.net.URL');
  } catch (e) { log('URL hook failed: ' + e); }

  try {
    var HUC = Java.use('java.net.HttpURLConnection');
    HUC.connect.implementation = function () {
      log('HttpURLConnection.connect ' + this.getURL().toString());
      log('     at ' + jstack());
      return this.connect();
    };
    log('hooked HttpURLConnection');
  } catch (e) { log('HttpURLConnection hook failed: ' + e); }

  /* ---------------------------------------------------------------- *
   * 3. popup / dialog creation
   * ---------------------------------------------------------------- */
  try {
    var B = Java.use('android.app.AlertDialog$Builder');
    B.show.implementation = function () {
      var r = this.show();
      log('*** AlertDialog$Builder.show() ***');
      log('     at ' + jstack());
      return r;
    };
    log('hooked AlertDialog$Builder.show');
  } catch (e) { log('AlertDialog hook failed: ' + e); }

  try {
    var D = Java.use('android.app.Dialog');
    D.show.implementation = function () {
      log('*** Dialog.show() on ' + this.getClass().getName() + ' ***');
      log('     at ' + jstack());
      return this.show();
    };
    log('hooked Dialog.show');
  } catch (e) { log('Dialog hook failed: ' + e); }

  try {
    var T = Java.use('android.widget.Toast');
    T.show.implementation = function () {
      log('Toast.show on ' + this.getClass().getName());
      return this.show();
    };
    log('hooked Toast.show');
  } catch (e) { log('Toast hook failed: ' + e); }

  try {
    var PW = Java.use('android.widget.PopupWindow');
    PW.showAtLocation.overload('android.view.View', 'int', 'int', 'int').implementation = function () {
      log('*** PopupWindow.showAtLocation ***');
      log('     at ' + jstack());
      return this.showAtLocation.apply(this, arguments);
    };
    log('hooked PopupWindow');
  } catch (e) { log('PopupWindow hook failed: ' + e); }

  /* ---------------------------------------------------------------- *
   * 4. the 9MOD mod classes
   * ---------------------------------------------------------------- */
  var modClasses = [
    'me.tiktokupdatez.f.a', 'me.tiktokupdatez.f.b', 'me.tiktokupdatez.f.c',
    'me.tiktokupdatez.f.d', 'me.tiktokupdatez.f.e', 'me.tiktokupdatez.f.g',
    'me.tiktokupdatez.f.h', 'me.tiktokupdatez.f.i', 'me.tiktokupdatez.f.j',
    'me.tiktokupdatez.b.a', 'me.tiktokupdatez.b.b', 'me.tiktokupdatez.b.c',
    'me.tiktokupdatez.b.d', 'me.tiktokupdatez.b.e', 'me.tiktokupdatez.b.f',
    'me.tiktokupdatez.a', 'me.tiktokupdatez.a.a',
    'me.tiktokupdatez.c.a', 'me.tiktokupdatez.d.a',
    'me.tiktokupdatez.CrashActivity'
  ];
  modClasses.forEach(function (c) {
    try {
      var C = Java.use(c);
      C.class.getDeclaredMethods().forEach(function (m) {
        var name = m.getName();
        try {
          C[name].overloads.forEach(function (ov) {
            ov.implementation = function () {
              var a = [];
              for (var i = 0; i < arguments.length; i++) {
                try { a.push(String(arguments[i]).substring(0, 200)); } catch (e) {}
              }
              var r = ov.apply(this, arguments);
              log('MOD ' + c + '.' + name + '(' + a.join(', ') + ')');
              return r;
            };
          });
        } catch (e) {}
      });
      log('hooked mod class ' + c);
    } catch (e) {}
  });

  /* ---------------------------------------------------------------- *
   * 5. TikTok's custom toast helper + BaseActivity
   *    NOTE: X.0w1M / X.0w1j are v46.7.5-specific obfuscated names.
   *    For other versions, run dexscan.py --classes to find the
   *    IActivityCustomToastHelper implementor in your version's dex.
   * ---------------------------------------------------------------- */
  hookAll('com.bytedance.ies.foundation.activity.IActivityCustomToastHelper',
          ['showCustomToast'], { stack: true });
  hookAll('X.0w1M', ['LIZ', 'showCustomToast', 'showCustomLongToast'], { stack: true });
  hookAll('X.0w1j', ['LIZ', 'onActivityResumed', 'onActivityCreated'], { stack: false });

  ['onCreate', 'onResume', 'onStart', 'onWindowFocusChanged', 'onPostResume', 'onNewIntent']
    .forEach(function (m) {
      hookAll('com.bytedance.ies.foundation.activity.BaseActivity', [m], {});
    });

  /* ---------------------------------------------------------------- *
   * 6. native payload entry
   *    NOTE: 'prime0.gold' is v46.7.5-specific.
   *    v46.3.5 uses 'probeq0.neonlia'. Use dexscan.py --classes to find.
   * ---------------------------------------------------------------- */
  hookAll('prime0.gold', ['registerNativesForClass'], {});
  hookAll('me.tiktokupdatez.a.a', ['run'], {});

  log('=== hooks installed, waiting for popup ===');
});
