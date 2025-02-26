// To do:
// * Different rule sets for some salts?
//   -- generate by set of disallowed characters
//   -- store disallowed set in localStorage along with the salt
// * Email passwords home
// * split out passwords into '1: p 2: a 3: s...' etc format for eg. bank?
// * encrypt password with a PIN and keep in localStorage
//   -- forget password after some number of tries

var Passgen = {};

// Calculate password from seed inputs.
Passgen.generatePassword = function(domain, pass, pepper, classes) {
    
    if (domain == '' || pass == '') {
        // Don't provide a 'default' password in case it gets
        // accidentally used.
        return '';
    }

    var len = 10;               // Password length
    var debug = false;

    // Allowed characters. No visually ambiguous characters, as
    // they're just a pain and we lose little by removing them.
    if (!classes) {
        classes = [ "ABCDEFGHJKLMNPQRSTUVWXYZ",
                    "abcdefghijkmnopqrstuvwxyz",
                    "23456789",
                    "-_:/*!$."
                  ];
    }
    var allowed = '';
    for (var i in classes) {
        allowed += classes[i];
    }

    var iteration = 0;

    do {
        var seasoned;
        if (pepper)
            seasoned = domain + '//' + pepper + '//' + pass;
        else
            seasoned = domain + '//' + pass;
        if (iteration != 0)
            seasoned += '//' + iteration;
        var hash = Sha256.hash(seasoned);
        var newpass = "";
        for (var i = 0; i < len; i++) {
            var c = parseInt(hash.substr(0, 2), 16);
            newpass += allowed.charAt(c % allowed.length);
            hash = hash.substr(2);
        }

        // Validate password contains at least one from each class.
        var class_ok = false;
        if (debug)
            console.log("Validate password '" + newpass + "' iteration " + iteration);
        for (var i in classes) {
            class_ok = false;
            for (var c in newpass) {
                if (classes[i].indexOf(newpass.charAt(c)) != -1) {
                    class_ok = true;
                    break;
                }
            }
            if (!class_ok) {
                if (debug)
                    console.log("*** Class " + i + " unsatisfied, try again");
                break;
            }
        }
        if (class_ok) {
            // Also enforce additional rule: no upper case at the
            // beginning of the password, no digits at the end.
            if (/^[A-Z]/.test(newpass) || /[0-9]$/.test(newpass)) {
                if (debug)
                    console.log("*** Abandon for ^[A-Z] or [0-9]$");
            } else {
                return newpass;
            }
        }
        iteration += 1;

    } while (1);
};

Passgen.generateLimitedPassword = function(domain, pass, pepper, disallow) {
    let rounds = 0;
    let p = '';
    for (;;) {
        pass = Passgen.generatePassword(domain, pass, pepper + p);
        rounds++;
        p =  '/' + rounds.toString();
        let ok = true;
        for (c of disallow.split('')) {
            if (pass.indexOf(c) != -1) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return pass;
        }
    }
}

// Find a pepper to generate a password with a specific prefix
Passgen.findMatch = function(domain, pass, match) {
    var i = 0;
    var gen;
    do {
        gen = Passgen.generatePassword(domain, pass, ""+i);
        if (gen.startsWith(match))
            break;
        if ((i & 0xffff) == 0)
            console.log("i is " + i + " generates " + gen);
        i++;
    } while (1);
    console.log("*** Got pepper of " + i + " to generate " + gen);
    return i;
}

Passgen.updateColour = function(pass) {
    var hash = Sha256.hash(pass.value);
    pass.style.backgroundColor = "#" + hash.substring(6, 12);
    pass.style.color = "#" + hash.substring(0, 6);
};

// Clean up a website domain.
Passgen.cleanDomain = function(domain) {
    domain = domain.toLowerCase();
    domain = domain.replace(/^https?:\/\//, '');
    domain = domain.replace(/\.(com|org|net|co.uk)$/, '');
    domain = domain.replace(/^www\./, '');
    domain = domain.replace(/^signin\./, '');

    // Map some website names...
    domain = domain.replace(/.*\.google$/, 'google');
    domain = domain.replace(/^(m|en)\./, '');

    // Wholly owned subsidiaries...
    domain = domain.replace('youtube', 'google');
    domain = domain.replace('flickr', 'yahoo');

    // Annoyances
    domain = domain.replace('bank.co-operativebank', 'co-operativebank');
    
    return domain;
};

// Update the HTML elements with a new password from the form, and
// select the text ready to be copied.
Passgen.updatePass = function(copy) {
    var output = document.getElementById('output_password');
    var domain = document.getElementById('input_domain').value;
    var pepper = document.getElementById('input_pepper').value;
    
    var pass = document.getElementById('input_password');
    var p = Passgen.generatePassword(domain, pass.value, pepper);
    Passgen.updateColour(pass);
    Passgen.setPepper(domain, pepper);
    output.value = p;
    output.select();
    if (copy) {
        document.execCommand("copy");
    }
};

// Split out search keys from URL.
Passgen.getSearchKeys = function() {
    if (document.location.search) {
        var s = document.location.search;
        if (s.charAt(0) == '?')
            s = s.substr(1);
        var kvs = s.split('&')
        var keys = {};
        for (var i in kvs) {
            kv = kvs[i].split('=')
            if (kv.length == 2) {
                k = decodeURI(kv[0]);
                v = decodeURI(kv[1]);
                keys[k] = v;
            } else if (kv.length == 1) {
                k = decodeURI(kv[0]);
                keys[k] = true;
            }
        }
        return keys;
    }
    return undefined;
};

// Clean up the salt/pepper map
Passgen.cleanSaltPepperMap = function(map) {
    let m = {};
    for (let line of map.split("\n")) {
        match = RegExp("^([^=]*)=(.+)$", "m").exec(line);
        if (match)
            m[match[1]] = line;
    }
    let l = [];
    for (let key in m) {
        l.push(m[key]);
    }
    return l.toSorted().join("\n");
};

Passgen.getPepper = function(salt) {
    let text = window.localStorage.getItem("salt_pepper_map");
    let re = RegExp("^"+salt+"=(.*)$", "m");
    match = re.exec(text);
    if (match) {
        return match[1];
    }
    return undefined;
}

Passgen.setPepper = function(salt, pepper) {
    let text = window.localStorage.getItem("salt_pepper_map");
    let re = RegExp("^"+salt+"=(.*)$", "m");
    match = re.exec(text);
    if (match) {
        text = text.replace(re, salt + "=" + pepper);
    } else {
        text = text + "\n" + salt + "=" + pepper + "\n"
    }
    text = Passgen.cleanSaltPepperMap(text);
    // Update storage and editor textarea
    window.localStorage.setItem("salt_pepper_map", text);
    document.getElementById('editor').value = text;
}

// Calculate a bookmarklet URL
Passgen.getBookmarkletURL = function() {
    var h = document.location.href;
    if (h.indexOf('?') != -1) {
        h += '&';
    } else {
        h += '?';
    }
    h += 'domain=';
    return "javascript:void(window.open('"+h+"'+document.location.hostname))";
}

Passgen.init = function() {
    
    $(document).ready(function() {
        
        // Update password on submit
        $('#passform').submit(function(event) {
            Passgen.updatePass(false);
            event.preventDefault();
        });
        
        $('#updateAndCopy').on("click", function(event) {
            Passgen.updatePass(true);
            event.preventDefault();
        });
        
        // On any change set to lowercase, thanks very much Android.
        $('#input_domain').change(function(event) {
            var t = document.getElementById('input_domain'); 
            var v = t.value.toLowerCase();
            if (v != t.value)
                t.value = v;

            // Also look up an appropriate pepper.
            let p = Passgen.getPepper(v);
            if (p) {
                document.getElementById('input_pepper').value = p;
            }
        });

        // Set input_domain from URL.
        keys = Passgen.getSearchKeys();
        if (keys && keys.domain) {
            var domain = Passgen.cleanDomain(keys.domain);
            document.getElementById('input_domain').value = domain;
            // Also allow some salt->pepper mapping from the URL.
            if (keys && keys["pepper_"+domain]) {
                document.getElementById('input_pepper').value
                    = keys["pepper_"+domain];
            }
            let p = Passgen.getPepper(v);
            if (p) {
                document.getElementById('input_pepper').value = p;
            }
            // Select input_password ready to start typing
            document.getElementById('input_password').select();
        }
        
        // Set URL of the bookmarklet
        document.getElementById('bookmarklet').href
            = Passgen.getBookmarkletURL();

        // Set value of editor.
        let editor_value = window.localStorage.getItem('salt_pepper_map');
        editor_value = Passgen.cleanSaltPepperMap(editor_value);
        document.getElementById('editor').value = editor_value;

        $('#editor_save').on('click', function(event) {
            window.localStorage
                .setItem('salt_pepper_map',
                         document.getElementById('editor').value);
        });

    });
    
    document.generatePassword = Passgen.generatePassword;
    document.updateColour = Passgen.updateColour;
    document.cleanDomain = Passgen.cleanDomain;
    document.updatePass = Passgen.updatePass;
    document.getSearchKeys = Passgen.getSearchKeys;
    document.getBookmarkletURL = Passgen.getBookmarkletURL;

}

try {
    exports.generatePassword = Passgen.generatePassword;
    exports.findMatch = Passgen.findMatch;
    exports.generateLimitedPassword = Passgen.generateLimitedPassword;
} catch(e) {
}
