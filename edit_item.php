<?php

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../templates/session.php';

$pageTitle = 'Edit Item';

// -----------------------------------------------------
// USER AUTHENTICATION
// Make sure that the user is logged in
// -----------------------------------------------------
if (!isset($_SESSION['user_id'])) {
    header('Location: ' . BASE_URL . '/pages/login.php');
    exit();
}

// ----------------------------------------------------------------------
// OWASP TOP 10 - A01:2021 BROKEN ACCESS CONTROL
// Verify that the user possesses the admin role
// ----------------------------------------------------------------------
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {

    // Return a 403 Forbidden HTTP status code, show an error message
    http_response_code(403);
    die('Error 403: Forbidden. You do not have permission to access this page.');
}

// ----------------
// INPUT VALIDATION
// ----------------
// filter_input with FILTER_VALIDATE_INT ensures item_id is an integer (prevents invalid input like "abc" or "<script>")
$item_id = filter_input(INPUT_GET, 'item_id', FILTER_VALIDATE_INT);
if ($item_id === false || $item_id === null) {
    http_response_code(400);
    die('Invalid item.');
}

// ----------------------
// HANDLE FORM SUBMISSION
// ----------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // If the token is missing or invalid, treat it as an invalid request
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
    http_response_code(400);
    die('Invalid request.');
    }

    // --------------------------------
    // PROCESS INPUTS AND SANITIZE THEM
    // --------------------------------
    // Remove any leading or trailing whitespaces
    $name = trim($_POST['name'] ?? '');
    // Treat the price as a numeric float
    $price = (float) ($_POST['price'] ?? 0);
    // Treat stock as an integer
    $stock = intval($_POST['stock'] ?? 0);
    // Store the description as plaintext and remove whitespaces
    $description = trim($_POST['description'] ?? '');
    // Store the description as plaintext and remove whitespaces
    $specifications = trim($_POST['specifications'] ?? '');

// ------------------------------------------------------------
// SECURE FILE UPLOAD - OWASP Top 10 - A04:2021 Insecure Design
// ------------------------------------------------------------
// null means admin did not upload a new image
$image_url = null;

// Firstly, ensure image is uploaded and PHP does not return an error
if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
    // This is the directory where the image is stored
    $uploadDir = __DIR__ . '/../assets/uploads/';
    // Temporary path where PHP stores the images
    $tmpPath   = $_FILES['image']['tmp_name'];

    // Image size cannot exceed 5MB (1KB is 1024 bytes. 1MB is 1024 KB. 5MB is 5 x 1024 x 1024 = 5242880 bytes)
    if ($_FILES['image']['size'] > 5242880) {
        $error = "File is too large. Max size is 5MB.";
    } else {
        // Validate the MIME type of the file (png, html etc.) using the finfo class
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $tmpPath);
        finfo_close($finfo);

        // Only accept the following MIME types
        $extMap = [
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/gif'  => 'gif',
            'image/webp' => 'webp',
        ];

        // If MIME type is not in the list above, return an error
        $fileExt = $extMap[$mime_type] ?? null;

        if (!$fileExt) {
            $error = "Invalid file type detected. Only actual images are allowed.";
        } else {

            // Generate a cryptographically secure filename
            $newFileName = bin2hex(random_bytes(16)) . '.' . $fileExt;
            // Path where the image will be saved on the server
            $destPath = $uploadDir . $newFileName;

            // Move file to the uploads folder
            // move_uploaded_file() ensures that the file designated by 'from' is a valid upload file 
            if (move_uploaded_file($tmpPath, $destPath)) {
                $image_url = $newFileName;
            } else {
                $error = "Failed to secure and move uploaded file.";
            }
        }
    }
}

    // -------------------------------------------------------------
    // SERVER-SIDE VALIDATION AND OWASP Top 10 - A03:2021-Injection)
    // -------------------------------------------------------------
    // Only insert the product if there was no error earlier, the required fields are filled and the price is not negative
    if (empty($error) && $name !== '' && $price > 0 && $stock >= 0 && $description !== '') {

        // Update image_url if a new image is uploaded
        if ($image_url !== null) {
            // Prepared statements to prevent SQL Injection (OWASP Top 10 - A03:2021-Injection)
            $stmt = $conn->prepare('UPDATE items SET name = ?, price = ?, stock_quantity = ?, description = ?, specifications = ?, image_url = ? WHERE item_id = ?');
            $stmt->bind_param('sdisssi', $name, $price, $stock, $description, $specifications, $image_url, $item_id);
        } else {
            // Keep old image
            $stmt = $conn->prepare('UPDATE items SET name = ?, price = ?, stock_quantity = ?, description = ?, specifications = ? WHERE item_id = ?');
            $stmt->bind_param('sdissi', $name, $price, $stock, $description, $specifications, $item_id);
        }

        // Execute the update
        if ($stmt->execute()) {
            header('Location: ' . BASE_URL . '/index.php');
            exit;
        } else {
            $error = 'Error updating item: ' . $stmt->error;
        }
        $stmt->close();
    } elseif (empty($error)) {
        $error = 'Please fill all fields correctly.'; // If there was no upload error but fields are invalid/missing, show generic form error
    }
}

// -----------------------------------------------------
// FETCH ITEM DETAILS (used to pre-fill the edit form)
// -----------------------------------------------------
$stmt = $conn->prepare('SELECT * FROM items WHERE item_id = ?');
$stmt->bind_param('i', $item_id);
$stmt->execute();
$result = $stmt->get_result();

// If no such item exists, return user to home page
if ($result->num_rows === 0) {
    header('Location: ' . BASE_URL . '/index.php');
    exit;
}

$item = $result->fetch_assoc();
$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <!-- Import Google Fonts used for the website -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link
        href="https://fonts.googleapis.com/css2?family=Cal+Sans:wght@400;500;600&family=Roboto:wght@300;400;500;700&display=swap"
        rel="stylesheet">
    <link rel="stylesheet" href="<?php echo BASE_URL; ?>/css/style.css">
</head>

<body>
    <?php include __DIR__ . '/../templates/header.php'; ?>

    <main class="container">
        <div class="card">
            <h2>Edit Item</h2>

            <!-- Display server-side errors if any -->
            <!-- htmlspecialchars prevents XSS if $error contains special chars -->
            <?php if (isset($error)): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <!-- Send form data to the same page using POST after validation is successful-->
            <form method="POST" action="" enctype="multipart/form-data" onsubmit="return validateProductForm()">

            <!-- This hidden input embeds a session-bound CSRF token in the form 
            so the server can verify that the submission is legitimate and not forged. -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(generateCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">

                <div class="form-group">
                    <label for="name">Item Name:</label>
                    <input type="text" id="name" name="name" maxlength="60"
                        value="<?php echo htmlspecialchars($item['name']); ?>" required>
                </div>

                <div class="form-group">
                    <label for="image">Change Image (Optional):</label>
                    <div style="margin-bottom: 10px;">
                        <!-- Show current image so admin knows what is currently set -->
                        <img src="<?php echo BASE_URL . '/assets/uploads/' . htmlspecialchars($item['image_url']); ?>"
                            alt="Current Image"
                            style="width: 100px; height: 100px; object-fit: contain; border: 1px solid #ddd; border-radius: 8px;">
                        <p style="font-size: 12px; color: #666; margin-top: 5px;">Current Image</p>
                    </div>

                    <!-- If left empty, the code keeps the old image_url -->
                    <input type="file" id="image" name="image" accept="image/*">
                    <small style="color:#666; font-size:12px;">Leave empty to keep the current image.</small>
                </div>

                <div class="card-row-split" style="display: flex; gap: 20px;">
                    <div class="form-group" style="flex: 1;">
                        <label for="price">Price ($):</label>
                        <!-- Pre-fill with existing price -->
                        <input type="number" id="price" name="price" step="0.01" min="0"
                            value="<?php echo htmlspecialchars($item['price']); ?>" required>
                    </div>

                    <div class="form-group" style="flex: 1;">
                        <label for="stock">Stock Quantity:</label>
                        <!-- Pre-fill with existing stock -->
                        <input type="number" id="stock" name="stock" min="0"
                            value="<?php echo htmlspecialchars($item['stock_quantity']); ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label for="description">Description:</label>
                    <!-- Pre-fill with existing description -->
                    <textarea id="description" name="description" maxlength="150" required><?php
                    echo htmlspecialchars($item['description']);
                    ?></textarea>
                </div>

                <div class="form-group">
                    <label for="specifications">Full Specifications:</label>
                    <!-- Specifications can be empty; ?? '' to avoid warnings -->
                    <textarea id="specifications" name="specifications" rows="6"><?php
                    echo htmlspecialchars($item['specifications'] ?? '');
                    ?></textarea>
                </div>

                <button type="submit" class="btn btn-primary">Update Item</button>
                <a href="<?php echo BASE_URL; ?>/index.php" class="btn">Cancel</a>
            </form>
        </div>
    </main>

    <?php include __DIR__ . '/../templates/footer.php'; ?>
    <script src="<?php echo BASE_URL; ?>/javascripts/script.js"></script>
</body>

</html>
<?php
if (isset($conn))
    $conn->close();
?>