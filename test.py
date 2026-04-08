#!/usr/bin/env python3

from MailTrace import render_analysis

raw = """Delivered-To: absentmindedmime@gmail.com
Received: by 10.140.42.20 with SMTP id b20csp51919qga;
        Mon, 21 Sep 2015 14:38:03 -0700 (PDT)
X-Received: by 10.180.24.72 with SMTP id s8mr14828708wif.49.1442871483088;
        Mon, 21 Sep 2015 14:38:03 -0700 (PDT)
Return-Path: <habiboucisse571@yahoo.com>
Received: from nm21-vm1.bullet.mail.ir2.yahoo.com (nm21-vm1.bullet.mail.ir2.yahoo.com. [212.82.96.252])
        by mx.google.com with ESMTPS id gx10si20043211wib.108.2015.09.21.14.38.02
        for <absentmindedmime@gmail.com>
        (version=TLS1 cipher=ECDHE-RSA-RC4-SHA bits=128/128);
        Mon, 21 Sep 2015 14:38:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of habiboucisse571@yahoo.com designates 212.82.96.252 as permitted sender) client-ip=212.82.96.252;
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of habiboucisse571@yahoo.com designates 212.82.96.252 as permitted sender) smtp.mailfrom=habiboucisse571@yahoo.com;
       dkim=pass header.i=@yahoo.com;
       dmarc=pass (p=REJECT dis=NONE) header.from=yahoo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=s2048; t=1442871482; bh=fn13UulOPPgL+ps4q0Shlg4CmeU2mneqoVejn8ypASs=; h=From:To:Subject:Date:From:Subject; b=Iz0aY1zJliBp7yUykvYCPW5i/vK/sXBAflgy3cqzaonMLFR3sZyioCoVb2dQ/FuKuHiT4CWJPr6HyofUifOAXHA2igqx/Of1h0N9Hv1VBZBUJmpu6DqLNQkqOzV8GY4izZkH6+I2LL4Ng0+BopsBItU5dAOlvsl8PqZuOUj7eNpbPjgGcfL8GSJZjWk8c3pIZK39FWV3Mj4iuJOea+jDCvQsM4vO3+uS1cFTj0NsGMOAaby/DFdxlvacOnxNGEzodPMx/hsldFCY/FQPFefYs4oC4LBRgv8Mskn8vmv1BI3i381IvK9n1PXeOpdZUNwn9/PNq1hS9Gw+eQK77Tv8jw==
Received: from [212.82.98.61] by nm21.bullet.mail.ir2.yahoo.com with NNFMP; 21 Sep 2015 21:38:02 -0000
Received: from [46.228.39.71] by tm14.bullet.mail.ir2.yahoo.com with NNFMP; 21 Sep 2015 21:38:02 -0000
Received: from [127.0.0.1] by smtp108.mail.ir2.yahoo.com with NNFMP; 21 Sep 2015 21:38:02 -0000
X-Yahoo-Newman-Id: 576812.13080.bm@smtp108.mail.ir2.yahoo.com
X-Yahoo-Newman-Property: ymail-3
X-YMail-OSG: lFF0gQgVM1nO_EgUelu6jUwGYY7ZAz1MzzjOu17hq.B_9NQ
 G.dtkSy8PhRWqqUtujtLNEJ.r8R1t_FHY6aJesfn8_RbQ1a5RPV9gpwWCpXx
 hRuetkvK5Z2iPD7K8yTRgW0MT.YU0Y4rBz542fH7PDHtPoAJU5W2BAXh0Cq7
 iRISzL9UP5fS.r6qEJDgrOWBiP.rs0O3aduYrOAsJDfXfV9P8Tfl8jXx_fq.
 dkWK3l5X_v03UHSq.Njq57GAnRQx25jrF1KenuB4iHve4arlD8hQ20OlbqXM
 hKyrh0vQGj.iEc5de1EiFKb8HqEpP_0B1s798L1rBHP12cEH9VDBdasBmaLa
 9ZvVVao1oR6gCXalxalntAaKei.e2_kRyHleOyCErUkziR0Zg.5IeeFmY.YM
 ZMioIvpXyrzbtToJIPF3Q.SaZ4kh0BoYylyzJ8P_352klOgWC99oF5kz4mXv
 3.mudKt9QICibAJEZ1x530MGHwyH3yGm5107dC7GIEhrzTVx6H58qKrm1JNH
 xVCNBw50X.7NWRJSj027XU2LdvIZS
X-Yahoo-SMTP: eaPXV.SswBBNFzZ2oWaEFM2I8.hIDYpTQMEvOg--
From: \"habiboucisse571\" <habiboucisse571@yahoo.com>
To: =?utf-8?B?Sm9zaWFoIFJvYmVydHM=?= <absentmindedmime@gmail.com>
Subject: Re: WhatsApp
X-Priority: 3
Importance: Normal
Date: Mon, 21 Sep 2015 21:37:45 GMT
MIME-Version: 1.0
X-Mailer: Infraware POLARIS Mobile Mailer v2.5
Content-Type: text/html; \tcharset=utf-8
Content-Transfer-Encoding: base64"""

render_analysis(raw)