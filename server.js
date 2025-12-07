require('dotenv').config({ debug: true });
const express = require('express');
const cors = require('cors');
var admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }))
app.use(cors({
    origin: '*'
}));

var cer = {
    "type": "service_account",
    "project_id": process.env.PROJECTID,
    "private_key_id": process.env.PRIVATEKEYID,
    "private_key": process.env.PRIVATEKEY,
    "client_email": process.env.CLIENTEMAIL,
    "client_id": process.env.CLIENTID,
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": process.env.CLIENTCERT,
    "universe_domain": "googleapis.com"
}

//initialize firebase admin
admin.initializeApp({
    credential: admin.credential.cert(cer)
});
const db = admin.firestore();

//map for encrypt and decrypt dictionary
let en_data = {
    'a': '8n', 'b': '37', 'c': 'Q8', 'd': 'zT', 'e': '1Z', 'f': '2Y', 'g': 'pj', 'h': '9wt', 'i': 'kz', 'j': '3s', 'k': 'rX', 'l': 'zb', 'm': 'sE', 'n': 'Mg', 'o': 'Ke', 'p': 'hP', 'q': 'nE', 'r': 'yB', 's': 'Pw', 't': 'xq', 'u': 'uT', 'v': '6v', 'w': 'T7', 'x': 'yI', 'y': 'CmW', 'z': 'R1',
    '0': 'Tk', '1': 'kV', '2': 'Bw', '3': 'zP', '4': 'Yo', '5': '4c', '6': 'Ar', '7': 'Dm', '8': 'U7', '9': 'Fw', ' ': 'qN', '.': 'vi', ',': 'Pq', ':': '3E'
}
const de_data = {};
for (const [key, value] of Object.entries(en_data)) {
    de_data[value] = key;
}
//encrypt function
function encrypt(e) {
    let encrypted = '';
    const normalizedText = e.toLowerCase();
    for (const char of normalizedText) {
        const substitution = en_data[char];
        if (substitution) {
            encrypted += substitution + 'a';
        } else {
            encrypted += char
        }
    }
    return encrypted.endsWith('a') ? encrypted.slice(0, -'a'.length) : encrypted
}
//decrypt function
function decrypt(e) {
    let text = '';
    const encrypt = e.split('a');
    for (const char of encrypt) {
        const origin = de_data[char];
        if (origin) {
            text += origin;
        } else {
            text += char
        }
    }
    return text
}
//generate student key
function generatekey(e) {
    let stringnum = String(e);
    let splitstring = stringnum.split('');
    let reversedstring = splitstring.reverse();
    let joinedstring = reversedstring.join('');
    let res = encrypt(joinedstring);
    return res;
}
//generate time
function getdate(e) {
    let jsdate = e.toDate();
    const formattedDate = jsdate.toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    return formattedDate;
}

const limiter = rateLimit({
    windowMs: 1 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Server can request 3 times per second, try again later!'
});
app.use(limiter);

app.get('/', (req, res) => {
    res.send('Home')
})
app.get('/key/:text', (req, res) => {
    let { text } = req.params;
    let gen = generatekey(text);
    res.send(gen)
})
const checkAuthToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authorization header is missing or malformed.' });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);

        req.user = decodedToken;

        next();

    } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(401).json({ error: 'Invalid or expired authentication token.' });
    }
};

//get all students
app.get('/api/lukhen', async (req, res) => {
    let got = await db.collection('students').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            registerdate: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All students data got.',
            data: d
        })
    }
})

//get specific student data with ID and Key
app.get('/api/lukhen/1/:id/:key', async (req, res) => {
    let { id, key } = req.params;
    let got = await db.collection('students').where('sid', '==', id).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'No student found with this ID!',
            data: []
        })
    } else {
        let gotstu = got.docs[0].data();
        if (gotstu.key === key) {
            res.json({
                status: 'success',
                text: 'All students data got.',
                data: gotstu
            })
        } else {
            res.json({
                status: 'fail',
                text: 'Invalid student key!',
                data: []
            })
        }
    }
})

//get specific student data with email and uid
app.get('/api/lukhen/email/:email/:id', async (req, res) => {
    let { email, id } = req.params;
    let got = await db.collection('students').where('accid', '==', id).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'No student found with this ID!',
            data: []
        })
    } else {
        let gotstu = got.docs[0].data();
        if (gotstu.email === email && gotstu.accid === id) {
            res.json({
                status: 'success',
                text: 'All students data got.',
                data: {
                    id: got.docs[0].id,
                    ...gotstu
                }
            })
        } else {
            res.json({
                status: 'fail',
                text: 'Invalid ID or Email!',
            })
        }
    }
})

//get all teachers
app.get('/api/mawsom', async (req, res) => {
    let got = await db.collection('teachers').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All teachers data got.',
            data: d
        })
    }
})

//get specific teacher data
app.get('/api/mawsom/:id/:key', async (req, res) => {
    let { id, key } = req.params;
    let got = await db.collection('teachers').where('tid', '==', id).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'No teacher found with this ID!',
            data: []
        })
    } else {
        let gotstu = got.docs[0].data();
        if (gotstu.key === key) {
            res.json({
                status: 'success',
                text: 'All teachers data got.',
                data: gotstu
            })
        } else {
            res.json({
                status: 'fail',
                text: 'Invalid teacher key!',
                data: []
            })
        }
    }
})

//get all activity video
app.get('/api/activityvideo', async (req, res) => {
    let got = await db.collection('activityvideo').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All activity video data got.',
            data: d
        })
    }
})

//get all project video
app.get('/api/projectvideo', async (req, res) => {
    let got = await db.collection('projectvideo').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All project video data got.',
            data: d
        })
    }
})

//get all reviews
app.get('/api/reviews', async (req, res) => {
    let got = await db.collection('reviews').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All reviews got.',
            data: d
        })
    }
})

//get recently two reviews
app.get('/api/recently/reviews', async (req, res) => {
    let got = await db.collection('reviews').orderBy('time', 'desc').limit(2).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All recently reviews were got.',
            data: d
        })
    }
})

//get recently activity video
app.get('/api/recently/activityvideo', async (req, res) => {
    let got = await db.collection('activityvideo').orderBy('time', 'desc').limit(1).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'Recently activity video was got.',
            data: d
        })
    }
})

//get recently project video
app.get('/api/recently/projectvideo', async (req, res) => {
    let got = await db.collection('projectvideo').orderBy('time', 'desc').limit(1).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'Recently project video was got.',
            data: d
        })
    }
})

//get total numbers for home page
app.get('/api/totalnumbers', async (req, res) => {
    let stugot = await db.collection('students').get();
    if (stugot.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong to get students data!',
            data: []
        })
    } else {
        let stunum = stugot.docs.length;
        let actgot = await db.collection('activityvideo').get();
        if (actgot.empty) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to get activity videos!',
                data: []
            })
        } else {
            let actnum = actgot.docs.length;
            let progot = await db.collection('projectvideo').get();
            if (progot.empty) {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong to get project videos!',
                    data: []
                })
            } else {
                let pronum = progot.docs.length;
                res.json({
                    status: 'success',
                    text: 'Data got.',
                    data: {
                        student: stunum,
                        activity: actnum,
                        project: pronum
                    }
                })
            }
        }
    }
})

//get recently announcement
app.get('/api/recently/announcement', async (req, res) => {
    let got = await db.collection('announcements').orderBy('time', 'desc').limit(2).get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'Recently announcement was got.',
            data: d
        })
    }
})
//get all announcements
app.get('/api/announcements', async (req, res) => {
    let got = await db.collection('announcements').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All announcements got.',
            data: d
        })
    }
})

//add new student
app.post('/api/sailukhen', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('students').add({
                name: recv.name,
                gender: recv.gender,
                address: recv.address,
                city: recv.city,
                parents: recv.parents,
                contact: recv.contact,
                birthdate: recv.birthdate,
                level: recv.level,
                status: 'attending',
                role: 'student',
                time: admin.firestore.FieldValue.serverTimestamp(),
                sid: recv.sid,
                accid: recv.accid,
                email: recv.email,
                key: generatekey(recv.sid)
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New student was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new student!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new student!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update student data
app.post('/api/maylukhen', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('students').doc(recv.docid).update({
                name: recv.name,
                gender: recv.gender,
                address: recv.address,
                city: recv.city,
                parents: recv.parents,
                contact: recv.contact,
                birthdate: recv.birthdate,
                level: recv.level,
                sid: recv.sid,
                accid: recv.accid,
                email: recv.email,
                key: generatekey(recv.sid)
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'Student was updated.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating student!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update student data!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update student data
app.post('/api/maylukheninfo', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('students').doc(recv.id).get();
        if (got.exists) {
            let sdata = got.data();
            if (sdata.email === recv.email && sdata.accid === recv.uid && sdata.sid === recv.sid) {
                try {
                    await db.collection('students').doc(recv.id).update(recv.data).then(() => {
                        res.json({
                            status: 'success',
                            text: 'Student was updated.',
                            data: []
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while updating student!',
                            data: []
                        })
                    })
                } catch (e) {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong to update student data!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'Invalid Email or 2 ID!'
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'Student data not found!'
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//delete student data
app.post('/api/morlukhen', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('students').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            if (gotdata.key === recv.key && gotdata.sid === recv.sid) {
                try {
                    await db.collection('deletedaccount').add({
                        name: recv.name,
                        gender: recv.gender,
                        address: recv.address,
                        city: recv.city,
                        parents: recv.parents,
                        contact: recv.contact,
                        level: recv.level,
                        birthdate: recv.birthdate,
                        sid: recv.sid,
                        accid: recv.accid,
                        email: recv.email,
                        key: generatekey(recv.sid)
                    }).then(async () => {
                        await db.collection('students').doc(recv.docid).delete().then(() => {
                            res.json({
                                status: 'success',
                                text: 'Student was deleted.',
                                data: []
                            })
                        }).catch((e) => {
                            res.json({
                                status: 'fail',
                                text: 'Something went wrong while deleting student!',
                                data: []
                            })
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while updating student!',
                            data: []
                        })
                    })
                } catch (e) {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong to update student data!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'ID and Key not same!',
                    data: []
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'No student found!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new teacher
app.post('/api/saimawsom', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('teachers').add({
                name: recv.name,
                gender: recv.gender,
                address: recv.address,
                city: recv.city,
                sub: recv.sub,
                contact: recv.contact,
                email: recv.email,
                status: 'active',
                role: 'teacher',
                time: admin.firestore.FieldValue.serverTimestamp(),
                tid: recv.tid,
                key: generatekey(recv.tid)
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New teacher was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new teacher!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new teacher!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update teacher data
app.post('/api/maymawsom', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('teachers').doc(recv.docid).update({
                name: recv.name,
                gender: recv.gender,
                address: recv.address,
                city: recv.city,
                contact: recv.contact,
                email: recv.email,
                tid: recv.tid,
                key: generatekey(recv.tid)
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'Teacher was updated.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating teacher!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update teacher data!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//delete teacher data
app.post('/api/mormawsom', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('teachers').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            if (gotdata.key === recv.key && gotdata.tid === recv.tid) {
                try {
                    await db.collection('deletedteacher').add({
                        name: recv.name,
                        gender: recv.gender,
                        address: recv.address,
                        city: recv.city,
                        sub: recv.sub,
                        email: recv.email,
                        contact: recv.contact,
                        tid: recv.tid,
                        key: generatekey(recv.tid)
                    }).then(async () => {
                        await db.collection('teachers').doc(recv.docid).delete().then(() => {
                            res.json({
                                status: 'success',
                                text: 'Teacher was deleted.',
                                data: []
                            })
                        }).catch((e) => {
                            res.json({
                                status: 'fail',
                                text: 'Something went wrong while deleting teacher!',
                                data: []
                            })
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while deleting teacher!',
                            data: []
                        })
                    })
                } catch (e) {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong to update teacher data!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'ID and Key not same!',
                    data: []
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'No teacher found!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new activity video
app.post('/api/saiactivityvideo', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('activityvideo').add({
                title: recv.title,
                thumb: recv.thumb,
                time: admin.firestore.FieldValue.serverTimestamp(),
                video: recv.video
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New activity video was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new activity video!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new activity video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update activity video data
app.post('/api/mayactivityvideo', async (req, res) => {
    let recv = req.body;
    console.log(recv);

    if (recv) {
        try {
            await db.collection('activityvideo').doc(recv.docid).update({
                title: recv.title,
                thumb: recv.thumb,
                video: recv.video
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'Activity video was updated.',
                    data: []
                })
            }).catch(error => {
                console.log(error);

                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating activity video!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update activity video data!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new project video
app.post('/api/saiprojectvideo', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('projectvideo').add({
                title: recv.title,
                thumb: recv.thumb,
                time: admin.firestore.FieldValue.serverTimestamp(),
                video: recv.video
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New project video was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new project video!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new project video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update project video data
app.post('/api/mayprojectvideo', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('projectvideo').doc(recv.docid).update({
                title: recv.title,
                thumb: recv.thumb,
                video: recv.video
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'Project video was updated.',
                    data: []
                })
            }).catch(error => {
                console.log(error);

                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating project video!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update project video data!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new review
app.post('/api/new/review', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('reviews').doc(recv.uid).set({
                email: recv.email,
                uid: recv.uid,
                text: recv.text,
                rating: recv.rating,
                name: recv.name,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New review was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new review!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new review!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//delete review
app.post('/api/morreview', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('reviews').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            if (gotdata.uid === recv.uid && gotdata.email === recv.email) {
                try {
                    await db.collection('deletedreviews').doc(gotdata.uid).set({
                        email: gotdata.email,
                        uid: gotdata.uid,
                        text: gotdata.text,
                        rating: gotdata.rating,
                        addtime: gotdata.time,
                        name: gotdata.name,
                        deletedtime: admin.firestore.FieldValue.serverTimestamp()
                    }).then(async () => {
                        await db.collection('reviews').doc(recv.docid).delete().then(() => {
                            res.json({
                                status: 'success',
                                text: 'Review was deleted.',
                                data: []
                            })
                        }).catch((e) => {
                            res.json({
                                status: 'fail',
                                text: 'Something went wrong while deleting review!',
                                data: []
                            })
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while deleting review!',
                            data: []
                        })
                    })
                } catch (e) {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong to update teacher data!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'UID and email not invild!',
                    data: []
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'No teacher found!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new announcement
app.post('/api/saianno', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('announcements').add({
                title: recv.title,
                msg: recv.msg,
                uid: recv.uid,
                email: recv.email,
                name: recv.name,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New announcement was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new announcement!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new announcement!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//delete announcement data
app.post('/api/moranno', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('announcements').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            try {
                await db.collection('deletedannouncements').add({
                    title: gotdata.title,
                    msg: gotdata.msg,
                    uid: gotdata.uid,
                    email: gotdata.email,
                    name: gotdata.name,
                    addedtime: gotdata.time,
                    deletedtime: admin.firestore.FieldValue.serverTimestamp()
                }).then(async () => {
                    await db.collection('announcements').doc(recv.docid).delete().then(() => {
                        res.json({
                            status: 'success',
                            text: 'Announcement was deleted.',
                            data: []
                        })
                    }).catch((e) => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while deleting announcement!',
                            data: []
                        })
                    })
                }).catch(error => {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong while deleting announcement!',
                        data: []
                    })
                })
            } catch (e) {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong to update announcement data!',
                    data: []
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'No announcement found!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

app.get('/isadmin', async (req, res) => {
    let { email, uid } = req.query;
    if (email && uid) {
        let got = await db.collection('admin').where('uid', '==', uid).get();
        if (got.empty) {
            res.json({
                status: 'fail',
                text: 'Only admin can access this API!'
            })
        } else {
            let da = got.docs[0].data();
            if (da.email === email && da.uid === uid) {
                res.json({
                    status: 'success',
                    text: 'You are admin.',
                    data: da
                })
            } else {
                res.json({
                    status: 'fail',
                    text: 'Only admin can access this API!'
                })
            }
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Email or UID was required!'
        })
    }
})

//add new form
app.post('/api/register', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('forms').add({
                time: admin.firestore.FieldValue.serverTimestamp(),
                status: 'pending',
                ...recv
            }).then(async (ad) => {
                let da = await ad.get();
                res.json({
                    status: 'success',
                    text: 'New form was added.',
                    data: {
                        id: ad.id,
                        registeredat: getdate(da.data().time),
                        ...da.data()
                    }
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new form!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new form!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get all forms
app.get('/api/forms', async (req, res) => {
    let got = await db.collection('forms').orderBy('time', 'desc').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            registerdate: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All forms got.',
            data: d
        })
    }
})
//get specific form
app.get('/api/get/register/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('forms').doc(id).get();
    if (got.exists) {
        let da = {
            registerdate: getdate(got.data().time),
            id: got.id,
            ...got.data()
        };
        res.json({
            status: 'success',
            text: 'Form was found.',
            data: da
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No form was found with this ID.'
        })
    }
})

//get all courses
app.get('/api/courses', async (req, res) => {
    let got = await db.collection('courses').orderBy('registertime', 'desc').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            registerdate: getdate(doc.data().registertime),
            launchdate: doc.data().launchtime ? getdate(doc.data().launchtime) : '',
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All courses got.',
            data: d
        })
    }
})
//add new course
app.post('/api/new/course', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('courses').add({
                registertime: admin.firestore.FieldValue.serverTimestamp(),
                launchtime: '',
                status: 'inactive',
                title: recv.title,
                type: recv.type,
                ownername: recv.ownername,
                owneremail: recv.owneremail,
                owneruid: recv.owneruid,
            }).then(async (ad) => {
                res.json({
                    status: 'success',
                    text: 'New course was added.',
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new course!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new course!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//add update course
app.post('/api/update/course', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('courses').doc(recv.id).update({
                title: recv.title,
                ownername: recv.ownername,
                owneremail: recv.owneremail,
                owneruid: recv.owneruid,
                type: recv.type
            }).then(async (ad) => {
                res.json({
                    status: 'success',
                    text: 'Course was updated.',
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating course!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update course!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//add edit course
app.post('/api/edit/course', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('courses').doc(recv.id).update({
                title: recv.title,
                des: recv.des,
                what: recv.what,
                price: recv.price,
                type: recv.type,
                thumb: recv.thumb,
                ownername: recv.ownername,
                owneraddr: recv.owneraddr,
                ownerphone: recv.ownerphone,
                owneracctype: recv.owneracctype,
                owneracc: recv.owneracc,
            }).then(async (ad) => {
                res.json({
                    status: 'success',
                    text: 'Course was updated.',
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while updating course!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to update course!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course
app.get('/api/get/course/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('courses').doc(id).get();
    if (got.exists) {
        let da = {
            registerdate: getdate(got.data().registertime),
            launchdate: got.data().launchdate ? getdate(got.data().launchdate) : '',
            id: got.id,
            ...got.data()
        };
        res.json({
            status: 'success',
            text: 'Form was found.',
            data: da
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No form was found with this ID.'
        })
    }
})

//get all posts for admin
app.get('/api/admin/posts/', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('posts').orderBy('time', 'desc').get();
    if (got.empty) {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    } else {
        let d = got.docs.map((doc) => ({
            id: doc.id,
            date: getdate(doc.data().time),
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All posts was got.',
            data: d
        })
    }
})
//get all posts
app.get('/api/posts/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Run the query
        const snapshot = await db.collection('posts')
            .where('courseid', '==', id)
            .get();

        // 2. Handle "No Data" naturally (Not an error)
        if (snapshot.empty) {
            return res.json({
                status: 'success',
                text: 'No posts found for this course.', // Informative text
                data: [] // Return empty array so frontend doesn't break
            });
        }

        let posts = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // 3. SORT MANUALLY HERE
        // This sorts the array by the 'time' field (Descending = Newest First)
        posts.sort((a, b) => {
            // Handle Firestore Timestamp objects (which have .seconds)
            if (a.time && b.time && a.time.seconds) {
                return b.time.seconds - a.time.seconds;
            }
            // Handle standard date strings/numbers
            return new Date(b.time) - new Date(a.time);
        });

        // 4. Format the date for the frontend AFTER sorting
        const finalData = posts.map(p => ({
            ...p,
            date: getdate(p.time) // Formatting function
        }));

        // 4. Return success
        res.json({
            status: 'success',
            text: 'All posts retrieved.',
            data: finalData
        });

    } catch (error) {
        // 5. Handle actual errors (Index missing, DB offline, etc.)
        console.error("Error fetching posts:", error);
        res.status(500).json({
            status: 'error',
            text: error.message, // Often helpful during dev, hide in production
            data: []
        });
    }
});
//add new post
app.post('/api/new/post', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('posts').add({
                time: admin.firestore.FieldValue.serverTimestamp(),
                text: recv.text,
                coursetitle: recv.coursetitle,
                courseid: recv.courseid,
                writername: recv.writername,
                writeremail: recv.writeremail,
                writeruid: recv.writeruid,
            }).then(async (ad) => {
                res.json({
                    status: 'success',
                    text: 'New post was added.',
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new post!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new post!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//delete course post
app.post('/api/delete/post', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('posts').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            if (gotdata.writeruid === recv.requesteruid && gotdata.writeremail === recv.requesteremail) {
                try {
                    await db.collection('deletedposts').add({
                        text: gotdata.text,
                        coursetitle: gotdata.coursetitle,
                        courseid: gotdata.courseid,
                        writername: gotdata.writername,
                        writeremail: gotdata.writeremail,
                        writeruid: gotdata.writeruid,
                        requesteruid: recv.requesteruid,
                        requesteremail: recv.requesteremail,
                        deletedtime: admin.firestore.FieldValue.serverTimestamp()
                    }).then(async () => {
                        await db.collection('posts').doc(recv.docid).delete().then(() => {
                            res.json({
                                status: 'success',
                                text: 'Post was deleted.',
                                data: []
                            })
                        }).catch((e) => {
                            res.json({
                                status: 'fail',
                                text: 'Something went wrong while deleting post!',
                                data: []
                            })
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while deleting post!',
                            data: []
                        })
                    })
                } catch (e) {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong to update post data!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'Permission required to request!',
                    data: []
                })
            }
        } else {
            res.json({
                status: 'fail',
                text: 'No post found!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})

//add new review
app.post('/api/new/course/review', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let fullid = recv.courseid + recv.uid;
            await db.collection('coursereviews').doc(fullid).set({
                email: recv.email,
                uid: recv.uid,
                text: recv.text,
                rating: recv.rating,
                name: recv.name,
                courseid: recv.courseid,
                coursename: recv.coursename,
                courseowneruid: recv.courseowneruid,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New review was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new review!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new review!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course reviews
app.get('/api/get/course/reviews/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursereviews').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Reviews were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No review was found with this ID.'
        })
    }
})
//add new course student request
app.post('/api/new/course/request', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('requestcourse').add({
                requestername: recv.requestername,
                time: admin.firestore.FieldValue.serverTimestamp(),
                coursename: recv.coursename,
                courseid: recv.courseid,
                courseowneremail: recv.courseowneremail,
                courseowneruid: recv.courseowneruid,
                requesteruid: recv.requesteruid,
                requesteremail: recv.requesteremail,
                accepteremail: '',
                accepteruid: '',
                status: "requested"
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'Your request was successfully added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while requesting to course!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to request course!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course students
app.get('/api/get/course/requests/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('requestcourse').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Requests were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No request was found with this ID.'
        })
    }
})
//get specific course students
app.get('/api/get/course/students/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursestudents').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            requesteddate: getdate(d.data().requestdate),
            acceptdate: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Students were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No student was found with this ID.'
        })
    }
})
//get specific course certificate
app.get('/api/get/course/certificate/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursecertificate').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            requesteddate: getdate(d.data().requestdate),
            acceptdate: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Certificates were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No certificate was found with this ID.'
        })
    }
})
//add new course student certificate
app.post('/api/new/course/certificate', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let id = recv.courseid + recv.studentuid;
            let got = await db.collection('coursestudents').doc(id).get();
            if (got.exists) {
                await db.collection('coursecertificate').add({
                    time: admin.firestore.FieldValue.serverTimestamp(),
                    coursename: recv.coursename,
                    courseid: recv.courseid,
                    courseowneremail: recv.courseowneremail,
                    courseowneruid: recv.courseowneruid,
                    studentname: recv.studentname,
                    studentuid: recv.studentuid,
                    studentemail: recv.studentemail,
                    accepteremail: recv.accepteremail,
                    accepteruid: recv.accepteruid,
                    note: recv.note,
                    rating: recv.rating,
                    status: recv.status,
                }).then(() => {
                    res.json({
                        status: 'success',
                        text: 'Your request was successfully added.',
                        data: []
                    })
                }).catch(error => {
                    res.json({
                        status: 'fail',
                        text: 'Something went wrong while requesting to course!',
                        data: []
                    })
                })
            } else {
                res.json({
                    status: 'fail',
                    text: 'No student found!',
                    data: []
                })
            }
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to request course!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//add accept student request
app.post('/api/accept/course/request', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let got = await db.collection('requestcourse').doc(recv.id).get();
            if (got.exists) {
                let gotdata = got.data();
                if (gotdata.courseowneremail === recv.accepteremail && gotdata.courseowneruid === recv.accepteruid) {
                    let did = got.id + gotdata.requesteruid;
                    await db.collection('coursestudents').doc(did).set({
                        studentname: gotdata.requestername,
                        time: admin.firestore.FieldValue.serverTimestamp(),
                        courseid: gotdata.courseid,
                        studentuid: gotdata.requesteruid,
                        studentemail: gotdata.requesteremail,
                        requestdate: gotdata.time,
                        accepteremail: recv.accepteremail,
                        accepteruid: recv.accepteruid,
                        courseowneremail: gotdata.courseowneremail,
                        courseowneruid: gotdata.courseowneruid
                    }).then(async () => {
                        await db.collection('requestcourse').doc(got.id).update({
                            status: 'accepted',
                            accepteremail: recv.accepteremail,
                            accepteruid: recv.accepteruid,
                        }).then(() => {
                            res.json({
                                status: 'success',
                                text: 'New student was accepted.',
                                data: []
                            })
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while accepting new student!',
                            data: []
                        })
                    })
                } else {
                    res.json({
                        status: 'fail',
                        text: 'No permission to reqest!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'No request found with thid ID!',
                    data: []
                })
            }
        } catch (e) {
            console.log(e);

            res.json({
                status: 'fail',
                text: 'Something went wrong to accept new student!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//add accept student request
app.post('/api/decline/course/request', async (req, res) => {
    let recv = req.body;
    console.log(recv);

    if (recv) {
        try {
            let got = await db.collection('requestcourse').doc(recv.id).get();
            if (got.exists) {
                let gotdata = got.data();
                if (gotdata.courseowneremail === recv.accepteremail && gotdata.courseowneruid === recv.accepteruid) {
                    await db.collection('requestcourse').doc(got.id).update({
                        status: 'rejected'
                    }).then(() => {
                        res.json({
                            status: 'success',
                            text: 'Requestation was rejected.',
                            data: []
                        })
                    })
                } else {
                    res.json({
                        status: 'fail',
                        text: 'No permission to reqest!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'No request found with thid ID!',
                    data: []
                })
            }
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to decline request!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course requests
app.get('/api/get/course/requests/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('requestcourse').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Requests were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No request was found with this ID.'
        })
    }
})
//check specific course student by uid and email
app.get('/api/check/course/student/:id', async (req, res) => {
    let { id } = req.params;
    let { uid, email } = req.query;
    let got = await db.collection('coursestudents').where('courseid', '==', id).where('studentuid', '==', uid).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            requesteddate: getdate(d.data().requestdate),
            acceptdate: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Students were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No student was found with this ID.'
        })
    }
})
//add new course video
app.post('/api/new/course/video', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('coursevideo').add({
                name: recv.name,
                des: recv.des,
                num: recv.num,
                link: recv.link,
                duration: recv.duration,
                courseid: recv.courseid,
                coursename: recv.coursename,
                courseowneruid: recv.courseowneruid,
                courseowneremail: recv.courseowneremail,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New video was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new video!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update course video
app.post('/api/update/course/video', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let got = await db.collection('coursevideo').doc(recv.id).get();
            if (got.exists) {
                if (got.data().courseowneruid === recv.requesteruid && got.data().courseowneremail === recv.requesteremail) {
                    await db.collection('coursevideo').doc(recv.id).update({
                        name: recv.name,
                        des: recv.des,
                        num: recv.num,
                        link: recv.link,
                        duration: recv.duration,
                    }).then(() => {
                        res.json({
                            status: 'success',
                            text: 'Video was updated.',
                            data: []
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while updating video!',
                            data: []
                        })
                    })
                } else {
                    res.json({
                        status: 'fail',
                        text: 'Permission required to request!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'No video found with this ID!',
                    data: []
                })
            }
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course videos
app.get('/api/get/course/videos/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursevideo').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Videos were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No video was found with this ID.'
        })
    }
})

//add new course document
app.post('/api/new/course/document', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('coursedocument').add({
                name: recv.name,
                des: recv.des,
                num: recv.num,
                link: recv.link,
                type: recv.type,
                courseid: recv.courseid,
                coursename: recv.coursename,
                courseowneruid: recv.courseowneruid,
                courseowneremail: recv.courseowneremail,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New document was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new document!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new document!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update course document
app.post('/api/update/course/document', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let got = await db.collection('coursedocument').doc(recv.id).get();
            if (got.exists) {
                if (got.data().courseowneruid === recv.requesteruid && got.data().courseowneremail === recv.requesteremail) {
                    await db.collection('coursedocument').doc(recv.id).update({
                        name: recv.name,
                        des: recv.des,
                        num: recv.num,
                        link: recv.link,
                        type: recv.type,
                    }).then(() => {
                        res.json({
                            status: 'success',
                            text: 'Document was updated.',
                            data: []
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while updating document!',
                            data: []
                        })
                    })
                } else {
                    res.json({
                        status: 'fail',
                        text: 'Permission required to request!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'No document found with this ID!',
                    data: []
                })
            }
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course documents
app.get('/api/get/course/documents/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursedocument').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Documents were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No document was found with this ID.'
        })
    }
})

//add new course discount
app.post('/api/new/course/discount', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            await db.collection('coursediscount').add({
                name: recv.name,
                code: recv.code,
                discount: recv.discount,
                expired: recv.expired,
                courseid: recv.courseid,
                coursename: recv.coursename,
                courseowneruid: recv.courseowneruid,
                courseowneremail: recv.courseowneremail,
                time: admin.firestore.FieldValue.serverTimestamp(),
            }).then(() => {
                res.json({
                    status: 'success',
                    text: 'New discount was added.',
                    data: []
                })
            }).catch(error => {
                res.json({
                    status: 'fail',
                    text: 'Something went wrong while adding new discount!',
                    data: []
                })
            })
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new discount!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//update course discount
app.post('/api/update/course/discount', async (req, res) => {
    let recv = req.body;
    if (recv) {
        try {
            let got = await db.collection('coursediscount').doc(recv.id).get();
            if (got.exists) {
                if (got.data().courseowneruid === recv.requesteruid && got.data().courseowneremail === recv.requesteremail) {
                    await db.collection('coursediscount').doc(recv.id).update({
                        name: recv.name,
                        code: recv.code,
                        discount: recv.discount,
                        expired: recv.expired,
                    }).then(() => {
                        res.json({
                            status: 'success',
                            text: 'Discount was updated.',
                            data: []
                        })
                    }).catch(error => {
                        res.json({
                            status: 'fail',
                            text: 'Something went wrong while updating discount!',
                            data: []
                        })
                    })
                } else {
                    res.json({
                        status: 'fail',
                        text: 'Permission required to request!',
                        data: []
                    })
                }
            } else {
                res.json({
                    status: 'fail',
                    text: 'No document found with this ID!',
                    data: []
                })
            }
        } catch (e) {
            res.json({
                status: 'fail',
                text: 'Something went wrong to add new video!',
                data: []
            })
        }
    } else {
        res.json({
            status: 'fail',
            text: 'Something went wrong!',
            data: []
        })
    }
})
//get specific course documents
app.get('/api/get/course/discounts/:id', async (req, res) => {
    let { id } = req.params;
    let got = await db.collection('coursediscount').where('courseid', '==', id).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Discounts were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No discount was found with this ID.'
        })
    }
})

//find student attended course
app.get('/api/find/course/:uid', async (req, res) => {
    let { uid } = req.params;
    let got = await db.collection('coursestudents').where('studentuid', '==', uid).get();
    if (!got.empty) {
        let all = got.docs.map((d) => ({
            date: getdate(d.data().time),
            id: d.id,
            ...d.data()
        }))
        res.json({
            status: 'success',
            text: 'Courses were found.',
            data: all
        })
    } else {
        res.json({
            status: 'fail',
            text: 'No course was found with this user ID.'
        })
    }
})

app.listen(80, () => {
    console.log('Server was started on port 80.');
})