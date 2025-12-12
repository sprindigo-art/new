<?php
// Aktifkan error reporting untuk debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// Fungsi validasi path dengan pengecekan ketat
function validatePath($path) {
    if (empty($path)) {
        throw new Exception("Path tidak boleh kosong");
    }
    $realPath = realpath($path);
    if ($realPath === false) {
        throw new Exception("Path tidak valid: " . htmlspecialchars($path));
    }
    $rootPath = realpath($_SERVER['DOCUMENT_ROOT']);
    if (strpos($realPath, $rootPath) !== 0) {
        throw new Exception("Path berada di luar root directory");
    }
    return $realPath;
}

// Fungsi untuk membersihkan nama file
function cleanFilename($filename) {
    $clean = preg_replace('/[^a-zA-Z0-9\-_\.]/', '_', $filename);
    return substr($clean, 0, 100);
}

// Fungsi buat zip pakai shell_exec
function createZipWithShell($sourcePath, $zipFilePath) {
    $escapedSource = escapeshellarg($sourcePath);
    $escapedZip = escapeshellarg($zipFilePath);

    $command = "zip -r $escapedZip $escapedSource";
    $output = shell_exec($command);

    if (!file_exists($zipFilePath)) {
        throw new Exception("Gagal membuat file ZIP.");
    }
}

try {
    $message = '';
    $zipCreated = false;
    $zipFileUrl = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['zip_path'])) {
        set_time_limit(0);
        ini_set('memory_limit', '-1');

        $pathToZip = $_POST['zip_path'];
        $zipName = isset($_POST['zip_name']) ? cleanFilename($_POST['zip_name']) : 'backup_' . date('Y-m-d_His');
        $validatedPath = validatePath($pathToZip);

        $zipFileName = $zipName . '.zip';
        $zipFilePath = __DIR__ . DIRECTORY_SEPARATOR . $zipFileName;

        createZipWithShell($validatedPath, $zipFilePath);

        $message = "File ZIP berhasil dibuat!";
        $zipCreated = true;
        $zipFileUrl = $zipFileName;
    }
} catch (Exception $e) {
    $message = "Error: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>ZIP Creator (Shell Version)</title>
</head>
<body>
    <h1>ZIP Creator (Shell Version)</h1>

    <?php if (!empty($message)): ?>
        <div><?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>

    <form method="POST">
        <label>Path Folder yang Mau Di-ZIP:</label><br>
        <input type="text" name="zip_path" value="<?php echo htmlspecialchars(__DIR__); ?>" required><br><br>

        <label>Nama File ZIP (tanpa .zip):</label><br>
        <input type="text" name="zip_name" value="<?php echo 'backup_' . date('Ymd_His'); ?>"><br><br>

        <button type="submit">Buat ZIP</button>
    </form>

    <?php if ($zipCreated): ?>
        <h3>File ZIP Berhasil Dibuat:</h3>
        <a href="<?php echo htmlspecialchars($zipFileUrl); ?>" download>Download <?php echo htmlspecialchars($zipFileUrl); ?></a>
    <?php endif; ?>
</body>
</html>
