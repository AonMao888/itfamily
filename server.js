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
    max: 3,
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
            ...doc.data()
        }))
        res.json({
            status: 'success',
            text: 'All students data got.',
            data: d
        })
    }
})

//get specific student data
app.get('/api/lukhen/:id/:key', async (req, res) => {
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
                        student:stunum,
                        activity:actnum,
                        project:pronum
                    }
                })
            }
        }
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
                birthdate:recv.birthdate,
                level: recv.level,
                status: 'attending',
                time: admin.firestore.FieldValue.serverTimestamp(),
                sid: recv.sid,
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
                birthdate:recv.birthdate,
                level: recv.level,
                sid: recv.sid,
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
                        birthdate:recv.birthdate,
                        sid: recv.sid,
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
                status: 'active',
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
//delete teacher data
app.post('/api/morreview', async (req, res) => {
    let recv = req.body;
    if (recv) {
        let got = await db.collection('reviews').doc(recv.docid).get();
        if (got.exists) {
            let gotdata = got.data();
            if (gotdata.uid === recv.uid && gotdata.email === recv.email) {
                try {
                    await db.collection('deletedreviews').doc(gotdata.uid).set({
                        email:gotdata.email,
                        uid:gotdata.uid,
                        text:gotdata.text,
                        addtime:gotdata.time,
                        deletedtime:admin.firestore.FieldValue.serverTimestamp()
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

app.listen(80, () => {
    console.log('Server was started on port 80.');
})