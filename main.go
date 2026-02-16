package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/mlkem"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type Message struct {
    Type      string          `json:"type"`
    Sender    string          `json:"sender"`
    Recipient string          `json:"recipient"`
    Timestamp int64           `json:"timestamp"`
    Payload   json.RawMessage `json:"payload"`
    Signature string          `json:"signature"`
}

type FileMetadata struct {
    Name        string   `json:"name"`
    Size        int64    `json:"size"`
    Hash        string   `json:"hash"`
    Permissions int      `json:"permissions"`
    Tags        []string `json:"tags"`
}

type DirectoryListing struct {
    Path      string         `json:"path"`
    Files     []FileMetadata `json:"files"`
    TotalSize int64          `json:"total_size"`
    FileCount int            `json:"file_count"`
}

type SecureChannel struct {
    conn         net.Conn
    sharedSecret []byte
    sendNonce    uint64
    recvNonce    uint64
}

func NewSecureChannel(conn net.Conn, secret []byte) *SecureChannel {
    return &SecureChannel{
        conn:         conn,
        sharedSecret: secret,
        sendNonce:    0,
        recvNonce:    0,
    }
}

func (sc *SecureChannel) EncryptAndSend(data []byte) error {
    nonce := make([]byte, 12)
    binary.BigEndian.PutUint64(nonce[4:], sc.sendNonce)
    sc.sendNonce++

    block, err := aes.NewCipher(sc.sharedSecret[:16])
    if err != nil {
        return err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    mac := hmac.New(sha256.New, sc.sharedSecret[16:32])
    mac.Write(data)
    signature := mac.Sum(nil)

    payload := make([]byte, 0)
    payload = append(payload, data...)
    payload = append(payload, signature...)

    encrypted := aesGCM.Seal(nil, nonce, payload, nil)

    length := uint32(len(encrypted))
    if err := binary.Write(sc.conn, binary.BigEndian, length); err != nil {
        return err
    }

    if _, err := sc.conn.Write(nonce); err != nil {
        return err
    }

    _, err = sc.conn.Write(encrypted)
    return err
}

func (sc *SecureChannel) ReceiveAndDecrypt() ([]byte, error) {
    var length uint32
    if err := binary.Read(sc.conn, binary.BigEndian, &length); err != nil {
        return nil, err
    }

    nonce := make([]byte, 12)
    if _, err := io.ReadFull(sc.conn, nonce); err != nil {
        return nil, err
    }

    encrypted := make([]byte, length)
    if _, err := io.ReadFull(sc.conn, encrypted); err != nil {
        return nil, err
    }

    expectedNonce := sc.recvNonce
    sc.recvNonce++

    actualNonce := binary.BigEndian.Uint64(nonce[4:])
    if actualNonce != expectedNonce {
        return nil, fmt.Errorf("nonce mismatch")
    }

    block, err := aes.NewCipher(sc.sharedSecret[:16])
    if err != nil {
        return nil, err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    payload, err := aesGCM.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, err
    }

    if len(payload) < 32 {
        return nil, fmt.Errorf("payload too short")
    }

    data := payload[:len(payload)-32]
    receivedSignature := payload[len(payload)-32:]

    mac := hmac.New(sha256.New, sc.sharedSecret[16:32])
    mac.Write(data)
    expectedSignature := mac.Sum(nil)

    if !hmac.Equal(receivedSignature, expectedSignature) {
        return nil, fmt.Errorf("signature mismatch")
    }

    return data, nil
}

type SecureFileTransfer struct {
    channel    *SecureChannel
    workingDir string
    sessionID  string
}

func NewSecureFileTransfer(channel *SecureChannel, workingDir string) *SecureFileTransfer {
    sessionID := make([]byte, 16)
    rand.Read(sessionID)

    return &SecureFileTransfer{
        channel:    channel,
        workingDir: workingDir,
        sessionID:  hex.EncodeToString(sessionID),
    }
}

func (sft *SecureFileTransfer) HandleClient() error {
    for {
        data, err := sft.channel.ReceiveAndDecrypt()
        if err != nil {
            if err != io.EOF {
                log.Printf("Receive error: %v", err)
            }
            return err
        }

        var msg Message
        if err := json.Unmarshal(data, &msg); err != nil {
            log.Printf("JSON unmarshal error: %v", err)
            continue
        }

        switch msg.Type {
        case "LIST_DIR":
            sft.handleListDirectory(msg)
        case "GET_FILE":
            sft.handleGetFile(msg)
        case "PUT_FILE":
            sft.handlePutFile(msg)
        case "DELETE_FILE":
            sft.handleDeleteFile(msg)
        case "MOVE_FILE":
            sft.handleMoveFile(msg)
        case "SEARCH":
            sft.handleSearch(msg)
        case "BATCH":
            sft.handleBatchOperation(msg)
        case "CLOSE":
            return nil
        }
    }
}

func (sft *SecureFileTransfer) handleListDirectory(msg Message) {
    var path string
    if err := json.Unmarshal(msg.Payload, &path); err != nil {
        sft.sendError(err)
        return
    }

    fullPath := filepath.Join(sft.workingDir, path)
    entries, err := os.ReadDir(fullPath)
    if err != nil {
        sft.sendError(err)
        return
    }

    var files []FileMetadata
    var totalSize int64

    for _, entry := range entries {
        info, err := entry.Info()
        if err != nil {
            continue
        }

        h := sha256.New()
        file, err := os.Open(filepath.Join(fullPath, entry.Name()))
        if err == nil {
            io.Copy(h, file)
            file.Close()
        }

        files = append(files, FileMetadata{
            Name:        entry.Name(),
            Size:        info.Size(),
            Hash:        hex.EncodeToString(h.Sum(nil)),
            Permissions: int(info.Mode().Perm()),
            Tags:        sft.generateTags(entry.Name()),
        })
        totalSize += info.Size()
    }

    listing := DirectoryListing{
        Path:      path,
        Files:     files,
        TotalSize: totalSize,
        FileCount: len(files),
    }

    payload, _ := json.Marshal(listing)
    response := Message{
        Type:      "LIST_RESULT",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   payload,
    }

    responseData, _ := json.Marshal(response)
    sft.channel.EncryptAndSend(responseData)
}

func (sft *SecureFileTransfer) handleGetFile(msg Message) {
    var fileInfo struct {
        Path   string `json:"path"`
        Resume bool   `json:"resume"`
        Offset int64  `json:"offset"`
    }

    if err := json.Unmarshal(msg.Payload, &fileInfo); err != nil {
        sft.sendError(err)
        return
    }

    fullPath := filepath.Join(sft.workingDir, fileInfo.Path)
    file, err := os.Open(fullPath)
    if err != nil {
        sft.sendError(err)
        return
    }
    defer file.Close()

    info, err := file.Stat()
    if err != nil {
        sft.sendError(err)
        return
    }
    _ = info

    if fileInfo.Resume {
        file.Seek(fileInfo.Offset, 0)
    }

    chunk := make([]byte, 65536)
    var offset int64 = fileInfo.Offset

    for {
        n, err := file.Read(chunk)
        if n > 0 {
            chunkData := struct {
                Path   string `json:"path"`
                Offset int64  `json:"offset"`
                Data   []byte `json:"data"`
                Eof    bool   `json:"eof"`
            }{
                Path:   fileInfo.Path,
                Offset: offset,
                Data:   chunk[:n],
                Eof:    false,
            }

            payload, _ := json.Marshal(chunkData)
            response := Message{
                Type:      "FILE_CHUNK",
                Sender:    "server",
                Recipient: msg.Sender,
                Timestamp: time.Now().Unix(),
                Payload:   payload,
            }

            responseData, _ := json.Marshal(response)
            sft.channel.EncryptAndSend(responseData)
            offset += int64(n)
        }

        if err == io.EOF {
            chunkData := struct {
                Path   string `json:"path"`
                Offset int64  `json:"offset"`
                Data   []byte `json:"data"`
                Eof    bool   `json:"eof"`
            }{
                Path:   fileInfo.Path,
                Offset: offset,
                Data:   []byte{},
                Eof:    true,
            }

            payload, _ := json.Marshal(chunkData)
            response := Message{
                Type:      "FILE_CHUNK",
                Sender:    "server",
                Recipient: msg.Sender,
                Timestamp: time.Now().Unix(),
                Payload:   payload,
            }

            responseData, _ := json.Marshal(response)
            sft.channel.EncryptAndSend(responseData)
            break
        }

        if err != nil {
            sft.sendError(err)
            return
        }
    }
}

func (sft *SecureFileTransfer) handlePutFile(msg Message) {
    var fileInfo struct {
        Path   string `json:"path"`
        Size   int64  `json:"size"`
        Hash   string `json:"hash"`
        Chunks int    `json:"chunks"`
    }

    if err := json.Unmarshal(msg.Payload, &fileInfo); err != nil {
        sft.sendError(err)
        return
    }

    fullPath := filepath.Join(sft.workingDir, fileInfo.Path)
    os.MkdirAll(filepath.Dir(fullPath), 0755)

    file, err := os.Create(fullPath)
    if err != nil {
        sft.sendError(err)
        return
    }
    defer file.Close()

    ack := Message{
        Type:      "PUT_ACK",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"ready":true}`),
    }
    ackData, _ := json.Marshal(ack)
    sft.channel.EncryptAndSend(ackData)

    h := sha256.New()
    writer := io.MultiWriter(file, h)

    for i := 0; i < fileInfo.Chunks; i++ {
        data, err := sft.channel.ReceiveAndDecrypt()
        if err != nil {
            sft.sendError(err)
            return
        }

        var chunkMsg Message
        json.Unmarshal(data, &chunkMsg)

        var chunk struct {
            Data  []byte `json:"data"`
            Index int    `json:"index"`
        }
        json.Unmarshal(chunkMsg.Payload, &chunk)

        writer.Write(chunk.Data)

        progress := Message{
            Type:      "PUT_PROGRESS",
            Sender:    "server",
            Recipient: msg.Sender,
            Timestamp: time.Now().Unix(),
            Payload:   json.RawMessage(fmt.Sprintf(`{"received":%d,"total":%d}`, i+1, fileInfo.Chunks)),
        }
        progressData, _ := json.Marshal(progress)
        sft.channel.EncryptAndSend(progressData)
    }

    computedHash := hex.EncodeToString(h.Sum(nil))
    if computedHash != fileInfo.Hash {
        os.Remove(fullPath)
        sft.sendError(fmt.Errorf("hash mismatch"))
        return
    }

    result := Message{
        Type:      "PUT_COMPLETE",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(fmt.Sprintf(`{"hash":"%s"}`, computedHash)),
    }
    resultData, _ := json.Marshal(result)
    sft.channel.EncryptAndSend(resultData)
}

func (sft *SecureFileTransfer) handleDeleteFile(msg Message) {
    var path string
    if err := json.Unmarshal(msg.Payload, &path); err != nil {
        sft.sendError(err)
        return
    }

    fullPath := filepath.Join(sft.workingDir, path)
    err := os.Remove(fullPath)

    if err != nil {
        sft.sendError(err)
        return
    }

    result := Message{
        Type:      "DELETE_COMPLETE",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"deleted":"` + path + `"}`),
    }
    resultData, _ := json.Marshal(result)
    sft.channel.EncryptAndSend(resultData)
}

func (sft *SecureFileTransfer) handleMoveFile(msg Message) {
    var paths struct {
        Source string `json:"source"`
        Dest   string `json:"dest"`
    }

    if err := json.Unmarshal(msg.Payload, &paths); err != nil {
        sft.sendError(err)
        return
    }

    sourcePath := filepath.Join(sft.workingDir, paths.Source)
    destPath := filepath.Join(sft.workingDir, paths.Dest)

    os.MkdirAll(filepath.Dir(destPath), 0755)
    err := os.Rename(sourcePath, destPath)

    if err != nil {
        sft.sendError(err)
        return
    }

    result := Message{
        Type:      "MOVE_COMPLETE",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"moved":true}`),
    }
    resultData, _ := json.Marshal(result)
    sft.channel.EncryptAndSend(resultData)
}

func (sft *SecureFileTransfer) handleSearch(msg Message) {
    var searchQuery struct {
        Pattern string   `json:"pattern"`
        Tags    []string `json:"tags"`
        MinSize int64    `json:"min_size"`
        MaxSize int64    `json:"max_size"`
    }

    if err := json.Unmarshal(msg.Payload, &searchQuery); err != nil {
        sft.sendError(err)
        return
    }

    var results []FileMetadata

    filepath.Walk(sft.workingDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }

        if info.IsDir() {
            return nil
        }

        relPath, _ := filepath.Rel(sft.workingDir, path)

        if searchQuery.Pattern != "" {
            matched, _ := filepath.Match(searchQuery.Pattern, info.Name())
            if !matched && !strings.Contains(relPath, searchQuery.Pattern) {
                return nil
            }
        }

        if searchQuery.MinSize > 0 && info.Size() < searchQuery.MinSize {
            return nil
        }

        if searchQuery.MaxSize > 0 && info.Size() > searchQuery.MaxSize {
            return nil
        }

        tags := sft.generateTags(info.Name())
        if len(searchQuery.Tags) > 0 {
            found := false
            for _, requiredTag := range searchQuery.Tags {
                for _, fileTag := range tags {
                    if requiredTag == fileTag {
                        found = true
                        break
                    }
                }
                if found {
                    break
                }
            }
            if !found {
                return nil
            }
        }

        h := sha256.New()
        file, _ := os.Open(path)
        io.Copy(h, file)
        file.Close()

        results = append(results, FileMetadata{
            Name:        relPath,
            Size:        info.Size(),
            Hash:        hex.EncodeToString(h.Sum(nil)),
            Permissions: int(info.Mode().Perm()),
            Tags:        tags,
        })

        return nil
    })

    payload, _ := json.Marshal(results)
    response := Message{
        Type:      "SEARCH_RESULT",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   payload,
    }
    responseData, _ := json.Marshal(response)
    sft.channel.EncryptAndSend(responseData)
}

func (sft *SecureFileTransfer) handleBatchOperation(msg Message) {
    var operations []struct {
        Type   string          `json:"type"`
        Params json.RawMessage `json:"params"`
    }

    if err := json.Unmarshal(msg.Payload, &operations); err != nil {
        sft.sendError(err)
        return
    }

    results := make([]map[string]interface{}, 0)

    for _, op := range operations {
        switch op.Type {
        case "GET_FILE":
            var path string
            json.Unmarshal(op.Params, &path)
            fullPath := filepath.Join(sft.workingDir, path)
            info, _ := os.Stat(fullPath)
            _ = info
            results = append(results, map[string]interface{}{
                "operation": "GET_FILE",
                "path":      path,
                "exists":    info != nil,
            })

        case "DELETE_FILE":
            var path string
            json.Unmarshal(op.Params, &path)
            fullPath := filepath.Join(sft.workingDir, path)
            err := os.Remove(fullPath)
            results = append(results, map[string]interface{}{
                "operation": "DELETE_FILE",
                "path":      path,
                "success":   err == nil,
            })

        case "CREATE_DIR":
            var path string
            json.Unmarshal(op.Params, &path)
            fullPath := filepath.Join(sft.workingDir, path)
            err := os.MkdirAll(fullPath, 0755)
            results = append(results, map[string]interface{}{
                "operation": "CREATE_DIR",
                "path":      path,
                "success":   err == nil,
            })
        }
    }

    payload, _ := json.Marshal(results)
    response := Message{
        Type:      "BATCH_RESULT",
        Sender:    "server",
        Recipient: msg.Sender,
        Timestamp: time.Now().Unix(),
        Payload:   payload,
    }
    responseData, _ := json.Marshal(response)
    sft.channel.EncryptAndSend(responseData)
}

func (sft *SecureFileTransfer) sendError(err error) {
    errorMsg := Message{
        Type:      "ERROR",
        Sender:    "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"error":"` + err.Error() + `"}`),
    }
    data, _ := json.Marshal(errorMsg)
    sft.channel.EncryptAndSend(data)
}

func (sft *SecureFileTransfer) generateTags(filename string) []string {
    tags := make([]string, 0)

    ext := strings.ToLower(filepath.Ext(filename))
    switch ext {
    case ".jpg", ".jpeg", ".png", ".gif":
        tags = append(tags, "image")
    case ".pdf", ".doc", ".docx", ".txt":
        tags = append(tags, "document")
    case ".mp3", ".wav", ".flac":
        tags = append(tags, "audio")
    case ".mp4", ".avi", ".mkv":
        tags = append(tags, "video")
    case ".zip", ".tar", ".gz":
        tags = append(tags, "archive")
    }

    if strings.Contains(filename, "backup") {
        tags = append(tags, "backup")
    }
    if strings.Contains(filename, "temp") {
        tags = append(tags, "temporary")
    }
    if strings.Contains(filename, "confidential") {
        tags = append(tags, "confidential")
    }

    return tags
}

func main() {
    os.MkdirAll("./server_files", 0755)
    os.MkdirAll("./client_files", 0755)

    var wg sync.WaitGroup
    wg.Add(2)

    go aliceServer(&wg)
    go bobClient(&wg)

    wg.Wait()
}

func aliceServer(wg *sync.WaitGroup) {
    defer wg.Done()

    listener, err := net.Listen("tcp", "localhost:8080")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    conn, err := listener.Accept()
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    dkAlice, err := mlkem.GenerateKey768()
    if err != nil {
        log.Fatal(err)
    }

    ekBytes := dkAlice.EncapsulationKey().Bytes()
    ekLen := uint16(len(ekBytes))
    lenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lenBuf, ekLen)

    if _, err := conn.Write(lenBuf); err != nil {
        log.Fatal(err)
    }

    if _, err := conn.Write(ekBytes); err != nil {
        log.Fatal(err)
    }

    ctLenBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, ctLenBuf); err != nil {
        log.Fatal(err)
    }
    ctLen := binary.BigEndian.Uint16(ctLenBuf)

    ciphertext := make([]byte, ctLen)
    if _, err := io.ReadFull(conn, ciphertext); err != nil {
        log.Fatal(err)
    }

    sharedSecretAlice, err := dkAlice.Decapsulate(ciphertext)
    if err != nil {
        log.Fatal(err)
    }

    channel := NewSecureChannel(conn, sharedSecretAlice)
    transfer := NewSecureFileTransfer(channel, "./server_files")

    fmt.Println("Alice: Secure file server ready")
    transfer.HandleClient()
}

func bobClient(wg *sync.WaitGroup) {
    defer wg.Done()

    var conn net.Conn
    var err error

    for i := 0; i < 10; i++ {
        conn, err = net.Dial("tcp", "localhost:8080")
        if err == nil {
            break
        }
        time.Sleep(100 * time.Millisecond)
    }

    if err != nil {
        log.Fatal("Failed to connect to server:", err)
    }
    defer conn.Close()

    lenBuf := make([]byte, 2)
    if _, err := io.ReadFull(conn, lenBuf); err != nil {
        log.Fatal(err)
    }
    ekLen := binary.BigEndian.Uint16(lenBuf)

    ekBytes := make([]byte, ekLen)
    if _, err := io.ReadFull(conn, ekBytes); err != nil {
        log.Fatal(err)
    }

    ekBob, err := mlkem.NewEncapsulationKey768(ekBytes)
    if err != nil {
        log.Fatal(err)
    }

    sharedSecretBob, ciphertext := ekBob.Encapsulate()

    ctLen := uint16(len(ciphertext))
    ctLenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(ctLenBuf, ctLen)

    if _, err := conn.Write(ctLenBuf); err != nil {
        log.Fatal(err)
    }

    if _, err := conn.Write(ciphertext); err != nil {
        log.Fatal(err)
    }

    channel := NewSecureChannel(conn, sharedSecretBob)

    fmt.Println("Bob: Connected to secure file server")

    testFile := []byte("This is a confidential document\nProject X - Launch codes: 4792-8841-AA38\nBackup codes: 7721-3365-ZZ91")
    os.WriteFile("./client_files/secret.txt", testFile, 0644)

    listDirMsg := Message{
        Type:      "LIST_DIR",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`"."`),
    }
    listData, _ := json.Marshal(listDirMsg)
    channel.EncryptAndSend(listData)

    response, _ := channel.ReceiveAndDecrypt()
    fmt.Printf("Directory listing: %s\n", string(response))

    searchMsg := Message{
        Type:      "SEARCH",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{"pattern":"*.txt","tags":["document"]}`),
    }
    searchData, _ := json.Marshal(searchMsg)
    channel.EncryptAndSend(searchData)

    response, _ = channel.ReceiveAndDecrypt()
    fmt.Printf("Search results: %s\n", string(response))

    closeMsg := Message{
        Type:      "CLOSE",
        Sender:    "bob",
        Recipient: "server",
        Timestamp: time.Now().Unix(),
        Payload:   json.RawMessage(`{}`),
    }
    closeData, _ := json.Marshal(closeMsg)
    channel.EncryptAndSend(closeData)

    fmt.Println("Bob: Session complete")
}
