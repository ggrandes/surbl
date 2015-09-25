/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.javastack.surbl;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

/**
 * Client SURBL - Spam URI Real-time Blackhole List
 * <p>
 * References:
 * <p>
 * <a href="http://www.surbl.org/redirection-sites">surbl - redirection-sites</a><br/>
 * <a href="http://www.surbl.org/guidelines">surbl - guidelines</a><br/>
 * <a href="http://multirbl.valli.org/list/">List of RBL</a><br/>
 * <a href="http://www.rfc-editor.org/rfc/rfc5782.txt">RFC5782 - DNS Blacklists and Whitelists</a><br/>
 */
public class SURBL {
	private static final Logger log = Logger.getLogger(SURBL.class);
	private static final String TWO_LEVEL_TLDS = "http://www.surbl.org/tld/two-level-tlds";
	private static final String THREE_LEVEL_TLDS = "http://www.surbl.org/tld/three-level-tlds";

	private final File storeDir;
	private final File storeLevel2;
	private final File storeLevel3;

	private volatile Set<String> set2 = null;
	private volatile Set<String> set3 = null;

	private int connectionTimeout = 30000;
	private int readTimeout = 60000;

	/**
	 * Create SURBL with default directory for cache file (<code>java.io.tmpdir</code>)
	 * 
	 * @throws IOException
	 */
	public SURBL() throws IOException {
		this(System.getProperty("java.io.tmpdir", "/tmp/"));
	}

	/**
	 * Create SURBL with specified directory for cache files
	 * 
	 * @param storeDirName directory for cache files
	 * @throws IOException
	 */
	public SURBL(final String storeDirName) throws IOException {
		storeDir = new File(storeDirName);
		if (!storeDir.exists()) {
			if (!storeDir.mkdirs())
				throw new IOException("Invalid storeDir: " + storeDirName);
		}
		storeLevel2 = new File(storeDir, "tlds.2");
		storeLevel3 = new File(storeDir, "tlds.3");
	}

	/**
	 * Set connection timeout
	 * 
	 * @param connectionTimeout millis
	 * @return
	 */
	public SURBL setConnectionTimeout(final int connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
		return this;
	}

	/**
	 * Set read timeout
	 * 
	 * @param readTimeout millis
	 * @return
	 */
	public SURBL setReadTimeout(final int readTimeout) {
		this.readTimeout = readTimeout;
		return this;
	}

	/**
	 * Load TLDs tables of two level and three level.
	 * 
	 * @return true if tables are reloaded, false if not reloaded
	 * @throws IOException
	 */
	public boolean load() throws IOException {
		final long now = System.currentTimeMillis();
		final long expire = (24 * 3600 * 1000L);
		boolean reload = false;
		// Get two-level-tlds
		if ((storeLevel2.lastModified() + expire) < now) {
			getTLDS(TWO_LEVEL_TLDS, storeLevel2);
			loadL2();
			reload = true;
		} else if (set2 == null) {
			loadL2();
			reload = true;
		}
		// Get three-level-tlds
		if ((storeLevel3.lastModified() + expire) < now) {
			getTLDS(THREE_LEVEL_TLDS, storeLevel3);
			loadL3();
			reload = true;
		} else if (set3 == null) {
			loadL3();
			reload = true;
		}
		return reload;
	}

	private void loadL2() throws IOException {
		set2 = Collections.unmodifiableSet(loadSetFromFile(storeLevel2, new HashSet<String>(8192)));
	}

	private void loadL3() throws IOException {
		set3 = Collections.unmodifiableSet(loadSetFromFile(storeLevel3, new HashSet<String>(4096)));
	}

	private static Set<String> loadSetFromFile(final File f, final Set<String> s) throws IOException {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(f));
			String line = null;
			while ((line = reader.readLine()) != null) {
				s.add(line);
			}
			log.info("Loaded " + s.size() + " TLDs from " + f.getName());
		} finally {
			closeSilent(reader);
		}
		return s;
	}

	private void getTLDS(final String inputUrl, final File cacheFile) throws IOException {
		final URL url = new URL(inputUrl);
		final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setConnectTimeout(connectionTimeout);
		conn.setReadTimeout(readTimeout);
		conn.setDoOutput(false);
		conn.setUseCaches(true);
		conn.setIfModifiedSince(cacheFile.lastModified());
		conn.connect();
		InputStream is = null;
		OutputStream os = null;
		try {
			is = conn.getInputStream();
			if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
				os = new FileOutputStream(cacheFile, false);
				byte[] buf = new byte[4096];
				int len = 0;
				while ((len = is.read(buf)) > 0) {
					os.write(buf, 0, len);
				}
				log.info("HTTP_OK: " + inputUrl);
			} else if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
				log.info("HTTP_NOT_MODIFIED: " + inputUrl);
			}
		} finally {
			closeSilent(is);
			closeSilent(os);
		}
	}

	/**
	 * Check if hostname is in SURBL
	 * 
	 * @param hostname to check in SURBL
	 * @return true if blacklisted
	 * @throws UnknownHostException if domain dont exist
	 * @throws MalformedURLException if url is malformed
	 */
	public boolean checkSURBL(final String hostname) throws MalformedURLException {
		final StringBuilder sb = new StringBuilder(hostname.length() + 16);
		final StringTokenizer st = new StringTokenizer(hostname, ".");
		final ArrayList<String> list = new ArrayList<String>();
		int levels = 2;
		while (st.hasMoreTokens()) {
			list.add(st.nextToken());
		}
		// Check IP addresses
		try {
			final InetAddress inetAddr = InetAddress.getByName(hostname);
			final String addr = inetAddr.getHostAddress();
			final String name = inetAddr.getHostName();
			if (addr.equals(name)) {
				if (inetAddr instanceof Inet4Address) {
					Collections.reverse(list);
					levels = 4;
				} else if (inetAddr instanceof Inet6Address) {
					throw new MalformedURLException("Unsupported IPv6");
				}
			}
		} catch (UnknownHostException e) {
			log.warn("UnknownHostException: " + hostname);
		}
		log.info("Domain tokens: " + list);
		if (list.size() < 2) // local hosts
			return false;
		while (true) {
			sb.setLength(0);
			getHostLevel(list, levels, sb);
			final String domCheck = sb.toString();
			if (levels == 2) {
				if (set2.contains(domCheck)) {
					levels++;
					continue;
				}
			} else if (levels == 3) {
				if (set3.contains(domCheck)) {
					levels++;
					continue;
				}
			}
			try {
				log.info("Checking SURBL(levels=" + levels + "): " + domCheck);
				if (InetAddress.getByName(sb.append(".multi.surbl.org.").toString()).getHostAddress()
						.startsWith("127.")) {
					log.info("SURBL checking (BANNED): " + domCheck);
					return true;
				}
			} catch (UnknownHostException ok) {
			}
			log.info("SURBL checking (CLEAN): " + domCheck);
			break;
		}
		return false;
	}

	private static void getHostLevel(final List<String> tokens, final int levels, final StringBuilder sb) {
		final int count = tokens.size();
		final int offset = count - levels;
		for (int i = 0; i < levels; i++) {
			sb.append(tokens.get(offset + i)).append('.');
		}
		sb.setLength(sb.length() - 1);
	}

	private static final void closeSilent(final Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable ign) {
			}
		}
	}
}
